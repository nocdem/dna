#!/usr/bin/env bash
# ════════════════════════════════════════════════════════════════════
# test_cmt_hf9.sh — HF-9 (plan docs/plans/approved/2026-11-04-hf9.md §12
# T-13, with the harness part of T-16): the generation-6 edge on the 7-node
# harness — populated legs, the param-24 vote, the edge at the end of block
# A−1, the eight keyed tries and the rendezvous storage assignment on 7/7,
# one node restarted across A, a fresh node replaying from genesis
# (standalone — NOT in the sweep)
# ════════════════════════════════════════════════════════════════════
#
# Governing records: the approved plan (operator 2026-11-04: "1 eveg 2
# duzelt 3 evet"; this package's brief: "Kodu Sonnet yazacak.") §4.2 (the
# eight legs), §5.1-5.3 (state, capture, flush), §6 (compositions), §7.1-7.3
# (param 24 / D6, the edge, the boundary table), §8.3-8.6 (the selector, the
# retained assignment, the boundary procedure, the transition at B1), §12
# (T-13, T-14, T-16 and the run list under the table), §13 (WP7), §16 (what
# is deferred). TEMPLATES (their helpers are copied, nothing is shared):
# test_cmt_hf8_gen5.sh (the capability gate, the six votes to generation 5,
# the vote helpers), test_storage_archive.sh (the storage CLI, the segment
# layout), test_cmt_blocksync.sh and test_v2_join.sh (stop / restart / wipe
# and rejoin a node), test_cmt_token_create.sh (the token). Every part that
# is new for HF-9 is marked "hf9:".
#
# TWO RUNS (plan §12, the paragraph under the table) — how each is started
#   SHORT EPOCH — "7/7 state_root at epoch length 15" (CLAUDE.md TESTS):
#     the whole scenario, storage included. Build, environment and command
#     sequence are below ("WHAT IT REQUIRES"). Parameters: E 15, BPY 20,
#     SAFETY grace 15, ERGONOMIC grace 15. Expected length ≈ 770 blocks
#     (JUDGMENT, not measured: the six votes ≈ 330, segment 1 at 390,
#     A ≈ 429, then 22 boundary cells B1 = 435 … 750 and the report window of
#     epoch 735 at tip 757, then the replay; the cell at boundary 720 is a
#     payday).
#   PRODUCTION-CONSTANT EDGE RUN — test parameters chosen by the
#     orchestrator (fix round 3, 2026-11-05, not a plan value): E = 720,
#     BPY = 6 307 200 (the shipped values, no -DDNAC_EPOCH_LENGTH /
#     -DDNAC_BLOCKS_PER_YEAR), SAFETY grace 15
#     (-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15, STAGEF_CC_GRACE_SAFETY=15)
#     and ERGONOMIC grace 720, the shipped value (no
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS, STAGEF_CC_GRACE_ERGONOMIC=720):
#     nodus_witness_vset.c:59 `_Static_assert(DNAC_CHAIN_CONFIG_GRACE_
#     ERGONOMIC_BLOCKS >= DNAC_EPOCH_LENGTH)` forbids ERGONOMIC 15 at E 720.
#     The production 17 280 SAFETY grace is NOT exercised: the run proves
#     the edge at E = 720, not the production wait. Length: the five
#     ERGONOMIC votes (params 7, 8, 9, 18, 22) each wait ≥ 725 blocks, so
#     ≈ 4 500 blocks (JUDGMENT) — hours even pumped. The script then runs `WITH_STORAGE=0`: everything up to and through the
#     edge (the votes, the REGISTRATION of the four storage members 4-7 at
#     generation 5 under their own keys — round-4 row 20, so leg 5 is populated
#     —, the populated legs, the param-24 vote, A−2 / A / A+1, the restart
#     across A, the fresh replay), and LEAVES OUT every other storage step
#     (segment 1, B1, join, exit, param 25) because a segment is P = 24 × E =
#     17 280 blocks at E = 720 and the first one is published at P + 2E =
#     18 720 — out of reach (plan §12: "P = 17280 is out of reach"). Leg 5
#     (registry) holds exactly the four registered members; leg 6 (segments) is
#     EMPTY on every node and the scenario asserts exactly that (its root must
#     equal the empty-leg root). The PASS line names E, BPY, both graces and
#     "WITHOUT storage segments".
#     SKIP (99) unless STAGEF_EPOCH_LENGTH is 15 (grace 15 / 15, BPY 20) or
#     720 (SAFETY 15, ERGONOMIC 720, BPY 6307200); BPY and payout_interval_
#     epochs are READ from the genesis document and printed.
#
# WHAT IT PROVES — each item would be false if it failed
#   0. Capability gate (FAIL): one version banner for the server and the CLI;
#      the CLI's chain-config usage names EVM_ACTIVE / RULESET_GEN_ROLES /
#      RULESET_GEN_ROOTS / RULESET_GEN_TRIE "exactly <D…>" and STORAGE_COPIES
#      "[4, 16]"; the usage's "vote wait N blocks" of RULESET_GEN_TRIE and
#      "one epoch, N blocks" of STORAGE_COPIES equal STAGEF_CC_GRACE_SAFETY
#      and STAGEF_EPOCH_LENGTH (the binary's constants, read from the binary
#      — an env var that does not match the build FAILs here); node 1's
#      database is schema S20 (the keyed-trie tables, the 24 triggers
#      "v2_trie_l<leg>_<ins|del|upd>", v2_trie_state.capture = 0); every
#      node's newest start logged the CLI's D4, D5 and D6.
#   1. Fresh chain: no row of params 7, 8, 9, 14, 16, 18, 22, 24, 25; no
#      v2_trie_roots row; no storage registration. Leaves are claimed by
#      nodes 1, 2, 4, 5, 6, 7 (node 3 = the pump's funder); node 1 creates a
#      token, node 2 registers a name (hf9: the populated legs 2 and 4; the
#      claims fill leg 3, the genesis outputs leg 1; validator_set_snapshots
#      and v2_attendance_epoch, legs 7 and 8, fill at the first boundaries).
#   2. The six votes of test_cmt_hf8_gen5.sh to generation 5 (HF2, HF3,
#      GEN2, EVM, ROLES, ROOTS), each row 7/7 and committed below its
#      effective height; the blocks AT H−1 / H / H+1 are compared 7/7 in the
#      FULL 64-byte mode at the FOUR generation edges GEN2, EVM, ROLES and ROOTS
#      (cross_edge). HF2 and HF3 (rows 7 and 8) only pump past their effective
#      height and wait — no three-height comparison there (round 10, row 17:
#      the header said "each of the six"; the comparisons were not added).
#      ruleset-info generation 5 at the end.
#   3. hf9 (short epoch only): nodes 4, 5, 6, 7 register as storage nodes
#      under their own keys; segment 1 is published at exactly 26 E (= P +
#      2E, the first storage boundary ≥ P + 2E), identical 7/7.
#   4. hf9: every one of the eight source tables is populated before the
#      edge (leg 6, the segments, only in the short run; leg 5, the four
#      registered storage members, in BOTH runs), and at the cell read BEFORE the
#      edge (tip ≤ A−2: v2_trie_state.capture = 0, no v2_trie_roots row, no
#      v2_trie_dirty row, no v2_storage_assign_state row) and at the cells
#      read AFTER it (tip ≥ A−1: capture = 1, eight v2_trie_roots rows,
#      v2_trie_dirty empty) the same eight snapshot reads on every live node
#      are BYTE-IDENTICAL: the tip, the full 64-byte global_root and block_id
#      of the listed heights, capture, dirty, the eight leg roots (each
#      root equals the empty-leg root SHA3-512(0x80) EXACTLY when its source
#      table — with the leg's row selection: leg 3 = target_domain_id 1 —
#      has no row, plan §4.1), and the storage relations below.
#   5. param 24 = D6 voted at A with A−1 and A not epoch boundaries (the
#      rule), the SAFETY wait; the edge line "HF-9: rule-set generation 5 -> 6
#      … at the end of height A−1 (param 24 RULESET_GEN_TRIE, D6 0x…)" on
#      every node; ruleset-info generation 6 with "this CLI carries it as
#      compiled generation 6"; tip A−2 is still generation 5.
#   6. Restart across A (hf9, T-13 "restart of one node across A"): node 3
#      is stopped once the fleet is at A−3 and restarted when the fleet is at
#      A+2. What is CHECKED (round 10, row 12): its OWN last applied height
#      after the stop is read and must be below A−1 (a restart across the
#      edge); the fleet tip at the restart is read and the number of blocks
#      the victim is behind is PRINTED. No exact gap and no Rule-N cap is
#      enforced (test_cmt_blocksync.sh's E/2 − 2 is only a reason for keeping
#      the gap short). It catches up THROUGH the edge block and then agrees
#      7/7: the full 64-byte global_root and block_id AT A−1, A and A+1, and
#      the leg roots and every relation of the snapshot read.
#   7. Short epoch only — the storage assignment (plan §8.4-8.6), read at the
#      first generation-6 boundary B1 = the first boundary ≥ A and at each
#      boundary of the events below, each as ONE snapshot per node:
#        a. at the edge (before B1): v2_storage_assign_state = (R 4,
#           boundary H2, xfer 1) with H2 the last boundary < A; the basis =
#           exactly the four members; segment 1 has four current rows, all
#           from_h = B1 (E-s2); v2_storage_member_epoch holds rows for H2−E
#           and H2 (E-s1); the frozen sets of H2−E and H2 name four members.
#        b. B1 (no event, previous relation XOR): R 4; segment 1 four current
#           rows; exactly ONE member has n_new = 1 (the one rendezvous adds
#           to the three XOR holders of four) and held_union = 1 for all
#           four; that member's grace_until = B1 + E, the others 0 (K9).
#        THE EVENT ORDER (plan T-16: "assert at least one changed holder per
#        case" — every asserted case changes a holder WHATEVER the
#        rendezvous scores are; the order is arranged for that, see the
#        comment at the start of section 6): B1 (4 members, R 4: XOR →
#        rendezvous, exactly one member gains, n_new 1, grace B1 + E); exit of
#        the exiter (a holder leaves: its rows end; R 4, three left hold; the
#        exiter is CHOSEN from the chain at B1 as a member with n_new 0, never
#        the B1 gainer — identities are fresh in every run); arrival
#        of the candidate (3 < R: it holds, n_new 1); the candidate's
#        DEPARTURE at the first freeze with fail_streak 3 (its row ends); join
#        of node 2 (3 < R: it holds); join of node 1 (setup: with five
#        eligible whether it holds depends on the scores — only the identities
#        rows inserted = rows ended = Σ n_new are asserted); copies UP 4 → 5
#        with five eligible (exactly one gains); copies DOWN 5 → 4 (exactly
#        one is dropped); copies UP 4 → 6 with five eligible (exactly one
#        gains); the candidate's REVIVAL (fail_streak 14 → 0) with six
#        eligible and R 6 (it holds). Each STORAGE_COPIES vote waits one epoch
#        (ERGONOMIC = E at the short build) and changes the next-but-one
#        boundary; the boundary before it still shows the old R.
#        The candidate: the funded identity cand1 (STAGEF_V2_CANDIDATES=1),
#        which runs NO node; registration has no reachability or role
#        requirement; every reporter finds it "never reachable on 0x72" in
#        each epoch in which it is eligible and FAILs it; each settlement
#        adds 1 to its fail_streak (3 … 14, 14 + 1 written as 0); it may stay
#        at a value (a settlement without half the power's reports moves
#        nothing, F1) but never skip or fall, and returns ONLY from 14 to 0
#        (track_d at every boundary); the loops are bounded (9 boundaries to
#        the departure, 20 epochs after it for the return). The boundary of
#        each event: the 7/7 full diff.
#      At every one of those boundaries: v2_storage_assign_state.boundary =
#      the boundary and copies = R(boundary); the basis = the registry's
#      ACTIVE members with fail_streak < 3; every published segment has
#      exactly min(R, |basis|) current rows, each on a basis member;
#      v2_storage_held = the per-member count of current rows;
#      v2_storage_member_epoch has one row per ACTIVE member at the
#      boundary and, for every row with n_new > 0, grace_until ≥ boundary +
#      n_new × E — and the whole relation (every row and column of all seven
#      storage tables) is identical on every live node (plan §8.4-8.5).
#   8. Short epoch only — T-16, harness half (plan §12 T-16: "the holder
#      runtime fetches the newly assigned segments and stops holding dropped
#      ones only after the overlap epoch"): every node that is a current
#      holder of segment 1 at every event boundary has the completeness
#      marker segments/seg-1.ok PRESENT at a tip below the next boundary (the
#      tip is read AFTER the file observation, round 10, row 6; the marker's
#      content, index and data are NOT validated by the harness — the segment
#      code validates them when it serves, segment.c:1004-1015, and an archive
#      holder's probes are answered from its block store first, reporter.c:281,
#      so only the pruned joiner's probes exercise a file; round 10, row 4); the exiter (a non-gainer
#      member of nodes 4-7, chosen at B1), taken out by its exit, and the member dropped by the copies decrease: (i) RETENTION is
#      asserted from the FILE ITSELF — seg-1.ok exists at a tip read before
#      and after the file test, both inside the overlap epoch [B, B + E − 1]
#      (round-4 row 11; nothing deletes it before the sweep of epoch B + E);
#      (ii) the DELETION HEIGHT from the holder runtime's own line "segment k
#      deleted … (H=…)" with H >= B + E (nodus_witness_storage_holder.c:283-288,
#      not "the file at tip X": a pump overshoots a height); that line is
#      logged AFTER the files went (segment.c:1193-1205), so it is WAITED for,
#      bounded by block distance and progress, and its absence FAILs (round-4
#      row 12). The deletion line alone proves WHEN, never that the file
#      existed before. The candidate is the non-serving case: it has no node,
#      hence no file.
#      THE FETCH PATH (round-4 row 5; holder.c:682-690 JOB_EXPORT when
#      nodus_seg_store_has, else JOB_FETCH): the joiner (node 2) REGISTERS
#      FIRST (it has no retain setting until then: AUTO keeps everything) and
#      only THEN is restarted, before the join boundary, with nodus.json
#      retain_blocks = evidence window + 2 (needs STAGEF_EVIDENCE_MAX_AGE_BLOCKS
#      / _DURATION_NS at the bring-up, the knobs of test_cmt_prune.sh; absent →
#      SKIP). As a storage member its retain height is min(tip − N + 1,
#      keep_from_segment, keep_from_unpublished) (nodus_witness_role_prune.c:
#      51-69): its must-hold list is empty until the join boundary and
#      keep_from_unpublished = P + 1 while segment 1 is the highest published,
#      so its block store is pruned to EXACTLY P + 1 — segment 1's range gone,
#      segment 2's whole range kept (asserted: base = P + 1 before the join
#      boundary, from its cmt_blockstore). An explicit retain set BEFORE the
#      registration pruned segment 2's range too (run 7) and broke K9a. K9a
#      premise (decision 2026-10-05-storage-reward-is-for-archive.md): before
#      EVERY segment publication boundary B = kP + 2E the block stores of all
#      registered storage members that run a node are read and must hold the
#      segment's whole range (base <= (k−1)P + 1, height >= kP + 1,
#      nodus_seg_store_has; assert_members_hold_range), else FAIL with a layout
#      message. READ TIP (round 9): the EARLIEST tip kP + 1 (a pump to it lands
#      at most 22 above; read_k9a_premise; segment 1 in section 3, segment k >= 2
#      right after the cell of the boundary kP), tip read before AND after the
#      store reads, both below B — the window [kP + 1, B − 1] is 2E − 1 heights
#      wide, not the single tip B − 1 of rounds 6-8 (run 10). The result relies,
#      between that tip and the holder's export / fetch decision after B, on the
#      unpublished-period guard of the retain height: min(tip − N + 1,
#      keep_from_segment, keep_from_unpublished), keep_from_unpublished =
#      seg_first(maxk + 1) = (k−1)P + 1 while k − 1 is the highest published
#      (nodus_witness_role_prune.c:51-69, :318-326) — no registered storage
#      member's store is pruned above the first height of segment k before it is
#      published. After its join the scenario
#      asserts the holder runtime's line "segment 1: fetching over 0x73 (the
#      block store no longer has the range)" (and NO "exporting" line for
#      segment 1) and its seg-1.ok. Its OK bit in its first eligible epoch is
#      then the segment FILE answering: the reporter answers from the block
#      store first and from the file only when the store lacks the sample
#      (nodus_witness_storage_reporter.c:280-286). Every other holder EXPORTS
#      from its (archive) store; for them a bit says "answers its probes",
#      not that a file was served.
#      The probe-report BITS (T-16 "the probe reports carry bits for the new
#      holders"). What a bit means, from source: v2_storage_reports.bitmap is
#      LSB-first, bit i = member i of the frozen set S(H) in node_fp ASC
#      order (nodus_witness.h, v2_storage_set_members "node_fp ASC is the
#      bitmap order"); a reporter sets bit i only when its probe of member i
#      answered OK; itself, a member with no eligible segment (in grace
#      included) and a failed or unreachable probe are bit 0 (nodus_witness_
#      storage_reporter.c). Which epoch: the joined member (node 2) is
#      eligible at H when H ≥ its grace_until and it has assignment rows at H
#      or H − E (nodus_witness_v2_storage.c eligible_segments / member_ks).
#      The reports of H are committed in the window (H + E, H + E + ⌊E/2⌋]
#      and pruned at H + 2E, so they are read at a tip in [H + E + ⌊E/2⌋,
#      H + 2E − 1], after every compared node was waited to the window's
#      close. For EVERY boundary epoch from B1 on: identical set / member_epoch
#      / report rows on 7/7; more than half the seats reported (F1); every
#      eligible member that runs a node has a certain OK verdict, the
#      candidate a certain NOT OK with bit 0 in every seat, a member in grace
#      or without assignment no bit; the actual NEW holders of each event
#      (members with n_new > 0, read from the member_epoch rows) are asserted
#      eligible with that bit in their first eligible epoch (their grace
#      end); the dropped holder carries no bit and held_union 0 one epoch
#      after its drop. The verdict is the SOURCE rule (nodus_witness_v2_
#      storage.c:1359-1397: seats counted by power, the owner-or-key
#      exclusion, 2·I ≤ P_total → NO_EVIDENCE, 3·Y > 2·I → OK). ROUND 10 (row
#      2): I and Y are COMPUTED with the source's exclusions, per member and
#      per reporting seat — a seat whose owner equals the member's owner
#      (registry payee_fp) or whose key equals the member's fp is skipped,
#      whatever its stored bit — from snapshot(H) (load_seats: seat key =
#      SHA3-512 of the entry's pubkey, owner = the entry's owner_fp, ruleset 2;
#      a ruleset-1 snapshot FAILs by name, its owner comes from a validator row
#      by migrated id the harness cannot derive). Equal seat power is READ at
#      every epoch read (check_verdict_prereqs): snapshot(H)
#      (validator_set_snapshots.snapshot_blob, the source the settlement reads)
#      holds N entries whose total_stake values are all equal and whose
#      snapshot hash is identical on every live node (the generation-4 edge's
#      self-delegations exist and are part of total_stake), so the power sums
#      are seat counts and P_total = N. NO_EVIDENCE FAILs as "undetermined";
#      the candidate must be NOT OK with bit 0 in every seat. The candidate's NOT OK is tied to the reporter's own
#      line "storage member <fp16>.. was never reachable on 0x72 in epoch
#      H=<H> — NOT OK" (reporter.c:579-580), at least one per reporting seat,
#      so "probed and unreachable" is told from "not probed" (both give bit 0).
#   8b. Short epoch only — SETTLEMENT (plan §12 T-13 "settlement / grace
#      effects"; §8.5 "Settlement at B for H = B − 2E: weight(m) = P × held_
#      union(m, H) unless m is in grace at H"). Pool 1 is FUNDED (the export
#      below). For every boundary epoch H from B1 on, read in its report
#      window (pool 1 and the owners' accrual change only at boundaries, so
#      the values read after H + E are the values the settlement at H + 2E
#      starts from) and checked after H + 2E: from the source (nodus_witness_
#      v2_storage.c st_settle, :1481-1521 weights, :1651-1690 pay) budget =
#      pool 1 >> 16 (NODUS_V2_GEN_REWARD_DIVISOR_LOG2, nodus_witness_v2_gen.h:
#      316); W = Σ held_union over the members not in grace (a NOT OK member's
#      weight counts); an OK member is paid floor(budget × held_union / W) to
#      its owner (here its own key: the accrual row of its fp), a NOT OK
#      member and a member in grace nothing; every owner's accrual rose by
#      exactly that and pool 1 fell by exactly the sum. Pool 1 is READ FROM
#      THE CHAIN (v2_treasury, above 2^17) before the storage part, and in
#      every paying epoch at least one paid member has a POSITIVE expected
#      share (an all-zero settlement FAILs; round-4 row 7). A settlement
#      boundary that is a PAYDAY (every payout_interval_epochs-th, read from
#      the genesis document) empties the accrual: not asserted, said so.
#      held_union and n_new are not their own oracle (round-4 row 8): for
#      every boundary after B1 they are DERIVED from the stored assignment
#      relation (current and ended rows, segments published <= B − E, members
#      of the set; plan :299-302) and must equal v2_storage_member_epoch, and
#      the settled epoch's held_union must equal that derivation. grace_until
#      is asserted as the exact recurrence max(previous boundary's value, B +
#      n_new × E), unchanged for n_new 0 (round-4 row 9), and fail_streak of
#      EVERY registry row as the exact source recurrence over the settled
#      epoch H = B − 2E (grace / verdict / weight read in its window; +0 or
#      +1 is no longer accepted; round-4 row 3). The two E-s1 epochs H2−E and
#      H2, settled at B1 and B1 + E, are read in their windows and checked
#      with the same formula (round-4 row 10), from the union counts the edge
#      STORED. NOT covered: those E-s1 union counts derived independently —
#      the previous relation is XOR (plan :306, dna_v2_segment_holders over the
#      segment root), which no table holds and this script does not
#      reimplement (and the same for held_union / n_new AT B1, which count
#      against XOR(set(H2))) — and epochs whose settlement lies beyond the end
#      of the run (none: the queued windows are drained, FAIL if pending).
#   9. A fresh node replaying from genesis (T-13): node 3 is stopped, its
#      databases are wiped (its identity kept), it is restarted with the
#      genesis pin only; its log (truncated first, so every line is of THIS
#      replay) carries the HF-7 edge line, the HF-9 edge line and a
#      generation-6 boundary; it reaches the fleet tip and agrees 7/7 in the
#      full 64-byte mode, leg roots and storage relations included.
#  10. No node logged "HF9-SHADOW FAULT" or "CMT_FAULT" (plan §11) during the
#      run; stagef_diff.sh is called ONLY with --full (T-14).
#
# WHAT IT REQUIRES
#   Compile flags — SHORT EPOCH: ONE short-epoch + short-grace build of THIS
#   tree (nodus-server AND nodus-cli from the SAME build dir, with
#   NODUS_EVM_ENABLED — the standalone non-Windows default: the generation-4,
#   -5 and -6 edges FAULT without it):
#     -DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20
#     -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15
#     -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15
#   (params 7, 8, 9, 18, 22, 25 are ERGONOMIC; params 14 and 24 are SAFETY.)
#   Optional TEST-OWNER build: PLUS the four flags stagef_hf6_owner.sh prints
#   (-DDNAC_HF6_FOUNDATION_OWNER, its D4, D5 and — HF-9 WP7 — D6; all or
#   none). With STAGEF_HF6_OWNER_KEYS set the scenario applies
#   test_cmt_hf8_gen5.sh's TEST-OWNER gate (keys, fp, not a node's) and,
#   after generation 4, checks that every validator is owned by that owner;
#   without it the K8 default is expected. Nothing else here needs the owner:
#   the storage members register under their OWN keys.
#   Compile flags — PRODUCTION-CONSTANT EDGE RUN: only the SAFETY grace
#   -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 (E = 720, BPY = 6 307 200 and
#   ERGONOMIC grace 720 are the defaults — no -DDNAC_EPOCH_LENGTH, no
#   -DDNAC_BLOCKS_PER_YEAR, no -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS);
#   with a TEST-OWNER the same four owner flags too.
#   Environment, ALL exported BEFORE stagef_up_v2.sh unless noted:
#     STAGEF_NODUS_BIN / STAGEF_NODUSCLI_BIN    that build
#     short epoch:   STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20
#       STAGEF_V2_CANDIDATES=1 (the candidate cand1: a genesis document
#       field — a different chain id; no cand1 → SKIP)
#       STAGEF_TREASURY_POOL1_RAW=1000000000000000 (pool 1 funded — the
#       settlement amounts are asserted; the script reads pool 1 FROM THE
#       CHAIN and FAILs below 2^17, it no longer reads this variable)
#       STAGEF_EVIDENCE_MAX_AGE_BLOCKS=10 STAGEF_EVIDENCE_MAX_AGE_DURATION_NS=
#       1000000 (NEW, round-4 row 5: the evidence window of test_cmt_prune.sh,
#       hashed into the genesis document — a different chain id; the joiner
#       node 2 is restarted, AFTER it registered, with retain_blocks = 12 so
#       that its block store is pruned to P + 1 (segment 1's range gone,
#       segment 2's kept) and the FETCH path runs; the script reads the
#       two values from the genesis document and SKIPs if the window is not
#       lowered (num_blocks < 100, duration < (blocks + 2) ms))
#     production-constant run: STAGEF_EPOCH_LENGTH and STAGEF_BLOCKS_PER_YEAR
#       unset (720 / 6307200); STAGEF_V2_CANDIDATES and
#       STAGEF_TREASURY_POOL1_RAW not needed
#     read by THIS script only: STAGEF_CC_GRACE_SAFETY=15 and
#       STAGEF_CC_GRACE_ERGONOMIC=15 (short run) / 720 (production-constant
#       run), else SKIP
#     optional: STAGEF_HF6_OWNER_FP_HEX / STAGEF_HF6_OWNER_KEYS (test owner)
#   Leave STAGEF_MODE (combined) and STAGEF_PAYOUT_INTERVAL_EPOCHS unset (24:
#   the settlement boundaries 360 and 720 are paydays, the script reads the
#   interval from the genesis document and does not assert those amounts).
#   Tools: sqlite3, xxd, ss, openssl (SHA3-512).
#   Exact command sequence (ORCHESTRATOR), short epoch, test-owner build:
#     S=<TREE>/nodus/tests/integration/stagef
#     bash $S/stagef_hf6_owner.sh /tmp/hf9-owner <TREE>/nodus/build/nodus-server
#       (prints the owner fp and the four flags O / D / D5F / D6F)
#     F='-DDNAC_EPOCH_LENGTH=15 -DDNAC_BLOCKS_PER_YEAR=20 -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15 -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'
#     cmake -S <TREE>/nodus -B <TREE>/nodus/build-hf9 -DCMAKE_C_FLAGS="$F $O $D $D5F $D6F"
#     make -C <TREE>/nodus/build-hf9 -j"$(nproc)" nodus-server nodus-cli
#     export STAGEF_NODUS_BIN=<TREE>/nodus/build-hf9/nodus-server
#     export STAGEF_NODUSCLI_BIN=<TREE>/nodus/build-hf9/nodus-cli
#     export STAGEF_EPOCH_LENGTH=15 STAGEF_BLOCKS_PER_YEAR=20 STAGEF_V2_CANDIDATES=1
#     export STAGEF_TREASURY_POOL1_RAW=1000000000000000
#     export STAGEF_EVIDENCE_MAX_AGE_BLOCKS=10 STAGEF_EVIDENCE_MAX_AGE_DURATION_NS=1000000
#     export STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=15
#     export STAGEF_HF6_OWNER_FP_HEX=<fp> STAGEF_HF6_OWNER_KEYS=/tmp/hf9-owner/identity
#     bash $S/stagef_up_v2.sh
#     bash $S/tests/test_cmt_hf9.sh; echo "rc=$?"
#     bash $S/stagef_down.sh
#   (without the owner: drop the first command, $O $D $D5F $D6F and the two
#   STAGEF_HF6_OWNER_* exports.) Production-constant edge run: the same with
#   F='-DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15'
#   (no -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS: the default 720 is
#   required by nodus_witness_vset.c:59), STAGEF_EPOCH_LENGTH /
#   STAGEF_BLOCKS_PER_YEAR / STAGEF_V2_CANDIDATES / STAGEF_TREASURY_POOL1_RAW
#   unset, STAGEF_CC_GRACE_SAFETY=15 STAGEF_CC_GRACE_ERGONOMIC=720.
#   (The short run also exports STAGEF_V2_CANDIDATES=1 and
#   STAGEF_TREASURY_POOL1_RAW=1000000000000000 next to the line above.)
#   SKIP (rc 99): a binary missing, STAGEF_EPOCH_LENGTH not 15 or 720 or the
#   genesis epoch_length differing, the graces not 15 / 15 (E 15) or 15 / 720
#   (E 720), the genesis blocks_per_year not 20 (E 15) or 6307200 (E 720), the
#   short run without the candidate identity cand1 (STAGEF_V2_CANDIDATES=1) or
#   without the lowered evidence window in the genesis document, a payout
#   interval of 1, a tool
#   missing, STAGEF_HF6_OWNER_KEYS set but unusable is a FAIL (not a skip),
#   not a Comet cluster, no $BASE_DIR/v2_genesis.conf, any split
#   STAGEF_MODE. A skip is not a pass.
#   FAIL (rc 1) on the capability gate (above), on a chain that already holds
#   any of the rows of item 1, on a leaf already claimed, and when there is no
#   pump (the script `die`s: round-4 row 23 — it was listed as a SKIP here),
#   and on pool 1 below 2^17 on the chain.
#
# WHAT IT LEAVES BEHIND
#   HF-2, HF-3, rule-set generations 2, 3 (+ the EVM domain), 4, 5 and 6 —
#   all one-way; chain_config_history rows for params 7, 8, 9, 14, 18, 22,
#   24 (and 25 in the short run). The HF-6 migration's rows, the HF-7 seed,
#   the eight keyed tries (v2_trie_nodes / v2_trie_roots) with capture = 1.
#   One v2_names row, one tokens row, the leaves of nodes 1, 2, 3 (the
#   pump), 4, 5, 6, 7 claimed. Short run: four storage nodes registered at
#   generation 5 (nodes 4, 5, 6, 7), nodes 2 and 1 registered later, the exiter
#   (one of nodes 4-7, chosen at B1) RELEASED (its bond back as one locked coin, output_index 201), segment 1
#   published plus a second (due at 750), segment files under
#   node<N>/data/segments, three STORAGE_COPIES rows (5, 4, 6), the
#   candidate cand1's leaf claimed and cand1 registered as a storage member
#   that runs no node (ACTIVE and back in the basis after its return, its bond
#   locked; round 10, row 13: NOT "fail_streak 0, in grace" — the drain keeps
#   going through its first eligible epochs, which are NOT OK because it runs
#   no node, and their settlements move its fail_streak again; the counter is
#   asserted exactly at every boundary cell, not as a final value), pool 1
#   debited by the settlements. Node 3 restarted once and then wiped and rejoined (its
#   nodus.log truncated, a new pid in pids.txt, its databases rebuilt).
#   $BASE_DIR/hf9/ (every CLI log, consent files). Tear down with
#   stagef_down.sh before re-running (every switch is one-way, every leaf and
#   param row single-use).
#
# HOW IT CAN LIE
#   - E = 15, grace 15 / 15, BPY 20 prove the LOGIC, not the production 720 /
#     17 280 / 720. The production-constant run (E 720, BPY 6307200, SAFETY
#     15, ERGONOMIC 720 — test parameters of the orchestrator) proves the
#     edge at E = 720 and says in its PASS line what it leaves out; the
#     17 280 SAFETY wait is not exercised.
#   - **PER-HEIGHT LEG ROOTS ARE NOT COVERED AT B1, B1+E AND B1+2E** (round-4
#     row 1). The plan (docs/plans/approved/2026-11-04-hf9.md :453) lists "leg
#     roots at A−1, A, A+1, B1, B1+E, B1+2E"; v2_trie_roots keeps the LATEST root
#     of each leg only, there is no per-height history (plan §16 DF-3, :614:
#     proofs at historical heights are not built) and no node logs a leg root.
#     What this scenario does, exactly:
#       * A−1, A, A+1: the eight leg roots are read at a tip T from a window with
#         NO envelope and NO boundary (tx_count over A … T is 0, T before the
#         next boundary — asserted), so they are the roots of those heights; and
#         the FULL 64-byte global_root and block_id of each of those heights are
#         compared 7/7 (stagef_diff.sh --full, historical rows exist).
#       * B1, B1+E, B1+2E (and every later boundary): ONLY the full global_root
#         and block_id AT the height are compared 7/7 (--full), plus the eight
#         leg roots and every storage relation of one snapshot at a LATER tip T
#         (the boundary cell prints the envelope count over (B, T]; with
#         envelopes it says the snapshot is of a later state). The per-height
#         comparison of the leg roots AT B1, B1+E, B1+2E is NOT covered. The
#         global root of a height is bound to its leg roots through the
#         composition chain (plan §10.3, :396-397: leg → its composition → STOR v3
#         → SYS v7 → DomainHead v2 → domains_root → GLOBAL v2 = the AppHash), so
#         seven nodes agreeing on it is agreement on the composition, but no leg
#         root of that height is read or named.
#     At A−1 itself the window is, by inference from README "DELTA 1" (a block
#     whose global root differs from its predecessor's is followed by a proof
#     block at the 4 s timeout_commit pace; NOT measured), one such interval —
#     too short to read reliably, so it is not read there.
#   - The "cell" read is a bounded re-read of an expected asynchronous
#     condition (all live nodes report the same tip), bounded by BLOCK
#     DISTANCE (the highest tip may not pass MIN_TIP + E) and by PROGRESS (the
#     lowest tip must rise within 30 rounds of 1 s); nodes at one tip with
#     different content die at once (that is a divergence, never retried).
#   - The independent facts here are the empty-leg root (SHA3-512(0x80),
#     plan §4.1, computed by openssl), the source-table row counts, the
#     registry, the node identities and the n_new / row identities above;
#     the leg roots themselves are NOT recomputed (the oracle's KAT and the
#     unit tests do that, T-4 / T-5): equality of 8 stored roots on 7 nodes
#     proves agreement, not correctness. The HRW SCORES / ORDER are not
#     recomputed either (the selector against its oracle is T-4 / T-7); the
#     set of holders of segment 1 is read from the chain.
#   - **The fail-streak crossing is driven by a member that runs no node**
#     (the tree has no fault knob for the 0x72 serving side — test_storage_
#     archive.sh, HOW IT CAN LIE — and SIGSTOP of a validator breaks the
#     Rule-N cap): the chain is not told the candidate is dead, the
#     reporters find it unreachable. What is therefore NOT separated: a NOT
#     OK that comes from a failed answer (an answering node whose segment
#     file is wrong) — only "never reachable" is exercised; the 0x72 serving
#     side and its NOT OK-by-answer path are the unit tests'
#     (test_storage_probe / test_storage_b2). The crossing needs more than
#     half the power's reports every epoch (F1); a run where reports miss
#     their window only takes longer (the loops are bounded at 9 / 20
#     boundaries) and FAILs if the bound is exceeded — a false RED.
#     **NOT COVERED (round-4 row 4, stopped with evidence): a RUNNING member's
#     holder runtime changing at the eligibility crossing.** The departure
#     ends only the candidate's row (the three others already hold) and the
#     revival inserts only the candidate's rows, so no node's holder runtime
#     changes at either crossing: the plan's "holder runtime side across the
#     crossing" (:456) is not exercised. A running member would have to FAIL
#     its probes for three settled epochs: the tree has no fault knob for the
#     0x72 serving side (grep getenv in nodus_witness_storage_*.c finds none),
#     a member answers from its block store first (reporter.c:280-286) so
#     deleting its file changes nothing for an archive node, the holder
#     re-fetches a missing file at the next epoch (holder.c:263-285, :682-690)
#     so a deleted file is not a stable fault, and SIGSTOP of a validator is
#     Rule N's AUTO_RETIRE (README:916). What IS asserted: the candidate's
#     NOT OK is the reporter's "never reachable on 0x72 in epoch H=<H>" line
#     (probed and unreachable), told from NOPROBE (not probed).
#     Also not asserted: a kind-3 owner. A second segment IS published during
#     the run (due at 2P + 2E = 750) and the generic invariants cover it; the
#     event-boundary row counts (rows inserted / ended, Σ n_new) of the exit,
#     arrival, join and copies cases assume NO publication at their boundary
#     (a coincidence FAILs closed, a false RED, never a false pass; the
#     revival boundary counts publication and revival inserts apart).
#   - Which member a case changes (the gainer of the copies increase, the
#     dropped holder of the decrease) depends on the node identities of the
#     run (the rendezvous scores); the scenario READS it from the rows and
#     asserts that exactly one changed. Only the join of node 1 (setup) is
#     not deterministic and no case is claimed for it.
#   - **The chain makes blocks on its own** (create_empty_blocks every 60 s,
#     timeout_commit 4 s, stagef_env.sh:1018-1056) while a step waits, so a
#     queued report window (8 heights, [H + E + E/2, H + 2E − 1]) can be OPEN
#     when a pump starts (round 8; run 9 passed epoch 525's window 547..554).
#     Every queued window and settlement is therefore served BEFORE any pump:
#     pump_to goes through advance_to whenever a check is queued, advance_to
#     serves first, stops at every window ahead and at every settlement
#     boundary, and the waits that do not pump (wait_seg_file, wait_seg_gone,
#     assert_deleted_at) serve the queues on each poll. NOT covered: the
#     waits that cannot serve (register_member, wait_cc_row, a node restart,
#     diff_full_at, cell_read) — if the chain passes a whole window (the tip at
#     or past H + 2E) during one of them, the run FAILs by name ("closed before
#     it could be read", a false RED, never a pass); nothing is retried or
#     lengthened.
#   - **Tip windows against the pump's landing and the chain's own blocks** (round
#     9). A pump to T returns as soon as tip >= T, lands at most 22 above T (a
#     spend is included within 20 heights of the tip it was sent at,
#     stagef_cmt_wait_row's budget, plus one block of poll granularity — inference),
#     and after a block that changed the app hash the chain makes the next block
#     on its own about 4 s later (proof block, cometbft v0.38.26
#     consensus/state.go:1101, :1113-1127) and an empty block every 60 s when
#     idle. Steps that needed one exact tip were widened or moved: the K9a
#     premise reads (above; run 10 read from tip 750 after landing on 749); the
#     pre-edge control (read at the lowest tip of the idle approach on seven
#     nodes, window [A−7, A−2], not [A−3, A−2] after the victim's stop); the
#     deletion waits (liveness bound one epoch after the sweeping boundary, not
#     4 blocks); the STORAGE_COPIES vote (the change may land at CUR_B + 2E or
#     CUR_B + 3E, copies_boundaries reads one cell per boundary); A (A % E in
#     [2, E − 8] in BOTH runs since round 10, distance B1 − A >= 8). Left unchanged and why: the overlap-file
#     check [B, B+E−1] (the evidence needs a tip >= B and < B+E; it runs first
#     after the cell, a named FAIL otherwise), cell_read's bound MIN_TIP + E (the
#     relations change at the next boundary), the registration / join windows
#     (the registration must land inside one epoch, a named FAIL; the join keeps
#     JOIN_PRUNE_MARGIN), the victim's stop at A−3 (2 blocks to A−1, at least two
#     idle intervals; its outage is the Rule-N-bounded one), cc_guard (4 blocks).
#   - **Every run asserts the same cases whatever keys it generates** (round 7).
#     The B1 gainer (the member with n_new 1) and the exiter (the lowest-numbered
#     member of nodes 4-7 with n_new 0 at B1, a current holder because R 4 = four
#     members) are READ from v2_storage_member_epoch at B1, so the gainer's bit
#     at epoch B1 + E and the exit (rows end, overlap retention, deletion line)
#     are both asserted in every run; the exiter is never the gainer, so the
#     gainer is still in set(B1 + E). Per later event: arrival and revival of the
#     candidate, the node 2 join (3 holders < R: it must hold) and the copies
#     events (exactly one member without a row gains / is dropped) do not
#     depend on which member the rendezvous picks; the node 1 join asserts only
#     the identity rows inserted = ended = Σ n_new; the dropped holder is read
#     from the rows (any holder, node 2 included). A member listed for a
#     check in an epoch whose frozen set it is not in FAILs by name.
#   - The verdict / payment assertions rest on the prerequisites READ at every
#     epoch read (equal total_stake of the N entries of snapshot(H), no owner
#     overlap — item 8; the generation-4 self-delegations exist and are part of
#     total_stake; the equal POWER follows from equal total_stake through
#     power_cap.c:87 (min(p, one cap)), which is not recomputed) and on pool 1 and the owners' accrual
#     changing only at boundaries (the read between boundaries is the
#     settlement's start value); a payday boundary is skipped, said so.
#   - The E-s1 union counts (epochs H2−E and H2) and held_union / n_new AT B1
#     are the stored values: deriving them needs the XOR relation of
#     set(H2), which no table holds (round-4 rows 8 and 10, stopped).
#   - Node 3 is the pump's funder: the pump reads node 1's database and
#     submits to node 1, using only node 3's identity FILES, never its
#     process (stagef_cmt_pump_to) — test_cmt_blocksync.sh keeps its victim
#     off the funder out of caution; here node 3 is the only node that is
#     neither a storage member, the proposer (node 1) nor the joiner
#     (node 2).
#   - The restart victim is stopped at the fleet tip A−3 and restarted when the
#     fleet reaches A+2; its OWN last applied height after the stop is read and
#     must be below A−1 (a restart across the edge), the fleet tip at the
#     restart is read, and the measured number of blocks behind is printed — no
#     fixed number is claimed; a longer gap risks Rule N (README), which would
#     show as a refused catch-up. Its leg roots are compared only after it is
#     back; while it is down the cells compare the six live nodes (the 7/7
#     full-mode diff at A−1 / A / A+1 is made after it caught up).
#   - A (the param-24 effective height) is moved to the next epoch's start + 2
#     when it would fall in the last two heights of an epoch (short run), so
#     the epoch H2−E settled at B1 can be read inside its window after the
#     restart cell; this shifts every later height by up to E.
#   - **The joiner's pruned store exists only because the evidence knob lowers
#     the window to 10 blocks.** At production constants an explicit retain must
#     exceed evidence max_age_num_blocks (default 100000, nodus_witness_cmt_node.c
#     :119-131), which is more than one segment (24 x 720 = 17280), and AUTO keeps
#     7 segments for a role and everything for no role: no member lacks a
#     published segment's range there. The harness reproduces a store without the
#     segment-1 range with the small window, laid out so that the K9a premise
#     (every member holds the range of a segment at its publication) still holds
#     and is READ from the stores before each publication; a layout that cannot
#     keep both FAILs as a layout failure (a false RED), it never weakens the
#     verdict rule. The retention restart needs JOIN_PRUNE_MARGIN (3) blocks
#     between the joiner's registration and the join boundary (a layout margin,
#     not a plan value).
#   - Duration ≈ 770 blocks short epoch (JUDGMENT, not measured: the six
#     votes ≈ 330, segment 1 at 390, A ≈ 429, B1 = 435, B_rel 450, candidate
#     arrival 465 / departure ≈ 540 / return ≈ 720 (3 NOT OK settlements, then
#     12 skipped), the last cell 750, the epoch-735 window at 757, then the
#     replay); ≈ 4 500 blocks production-constant run. rc 99 = coverage that
#     did not happen.
#
# ════════════════════════════════════════════════════════════════════
set -euo pipefail
. "$(dirname "$0")/../stagef_env.sh"
# hf9: ruleset-info, the vote path and the storage RPCs were not checked
# through a split core — SKIP (99) in every split mode (the HF-6 rule).
stagef_split_skip_if --reason "HF-9 generation-6 scenario not checked through a split core" \
    $(seq 1 "$STAGEF_COMMITTEE_SIZE")

die() { echo "[FAIL] $*" >&2; exit 1; }

S_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SRV="$STAGEF_NODUS_BIN"
CLI="$STAGEF_NODUSCLI_BIN"
PARAM_HF2=7                # DNAC_CFG_HF2_ACTIVE, value exactly 1
PARAM_HF3=8                # DNAC_CFG_HF3_ACTIVE, value exactly 1
PARAM_GEN2=9               # DNAC_CFG_RULESET_GEN2, value exactly D2
PARAM_EVM=14               # DNAC_CFG_EVM_ACTIVE, value exactly D
PARAM_RET16=16             # DNAC_CFG_RULESET_GEN_STORAGE — RETIRED
PARAM_HF6=18               # DNAC_CFG_RULESET_GEN_ROLES, value exactly D4
PARAM_HF7=22               # DNAC_CFG_RULESET_GEN_ROOTS, value exactly D5
PARAM_TRIE=24              # hf9: DNAC_CFG_RULESET_GEN_TRIE, value exactly D6
PARAM_COPIES=25            # hf9: DNAC_CFG_STORAGE_COPIES, [4, 16]
GEN_2=2                    # NODUS_RT_GEN_2
GEN_EVM=3                  # NODUS_RT_GEN_EVM
GEN_4=4                    # NODUS_RT_GEN_STORAGE
GEN_5=5                    # NODUS_RT_GEN_ROOTS
GEN_6=6                    # hf9: NODUS_RT_GEN_TRIE (nodus_witness_runtime.h)
GRACE_MARGIN=5             # the HF-2/HF-3/HF-4 template's +5
WINDOW_MARGIN=5            # the EVM template's F5 window margin
CC_GUARD_GAP=4             # the EVM template's epoch-boundary guard
PUMP_STOP_GAP=7            # the HF-4 template's idle window before an edge
A_MARGIN=20                # hf9: room between the param-24 vote and A (layout, not a timeout)
E_SHORT=15                 # the one epoch length whose segment (P = 24 E) is reachable
BOND=100000000000000       # DNAC_HF6_STORAGE_BOND_DEFAULT (test_storage_archive.sh)
CONSENT_AHEAD=150          # consent expiry = tip + this (test_storage_archive.sh)
A_ROOM=8                   # hf9: layout, not a plan value — blocks B1 - A must leave for the steps between A and B1 (see the A rule)
JOIN_PRUNE_MARGIN=3        # hf9: layout, not a timeout — blocks that must remain before the join boundary for the joiner's retention restart
K8_OWNER=8eff7f418ab7a4432118ff99e21f2c3d1baf186200c148a3bba7d274499386ac970e267a9c9b3bbc05bfff1c62a72d63f72a555db780feeaaad4fb49ba9f7b89
OWNER=$(printf '%s' "${STAGEF_HF6_OWNER_FP_HEX:-$K8_OWNER}" | tr 'A-F' 'a-f')
OWN_KEYS="${STAGEF_HF6_OWNER_KEYS:-}"
CONF="$BASE_DIR/v2_genesis.conf"
LOGD="$BASE_DIR/hf9"
N="$STAGEF_COMMITTEE_SIZE"
E="$STAGEF_EPOCH_LENGTH"
GRACE_ERG="$STAGEF_CC_GRACE_ERGONOMIC"
GRACE_SAF="$STAGEF_CC_GRACE_SAFETY"
VICTIM=3                   # hf9: restart across A and fresh replay (header, HOW IT CAN LIE)
JOINER=2                   # hf9: registers as a storage node after B1
EXITER=""                  # hf9: the storage node its owner takes out — CHOSEN at B1 from the chain: the lowest-numbered member of MEMBERS_PRE with n_new 0 (never the B1 gainer; node identities are generated fresh every run)
MEMBERS_PRE="4 5 6 7"      # hf9: registered at generation 5, before A
CAND="$BASE_DIR/cand1/identity"   # hf9: the storage member that runs no node (STAGEF_V2_CANDIDATES=1)
DIV_LOG2=16                # NODUS_V2_GEN_REWARD_DIVISOR_LOG2 (nodus_witness_v2_gen.h:316): budget = pool 1 >> 16
E_PROD=720                 # hf9: the production-constant run's epoch length
BPY_PROD=6307200           # hf9: its blocks per year (the shipped value)
NAME_B=hf9nameone          # hf9: node 2's name (9 characters)
TK_NAME="Harness HF9 Token"
TK_SYM="HF9"
TK_DEC=8
TK_SUPPLY=2100000000000000
EMPTY_ROOT=""              # hf9: SHA3-512(0x80), set by the gate
MSG_LAYOUT="the layout broke (a false RED, never a false PASS)"

# hf9: the short run covers storage, the production-constant run does not
WITH_STORAGE=0
if [ "$E" = "$E_SHORT" ]; then WITH_STORAGE=1; fi

# ── SKIP gates (rc 99 — a skip is not a pass) ───────────────────────
for pair in "STAGEF_NODUS_BIN=$SRV" "STAGEF_NODUSCLI_BIN=$CLI"; do
    name="${pair%%=*}"; bin="${pair#*=}"
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "[SKIP] $name is unset or not executable ('$bin') — this scenario needs a build of"
        echo "       this tree; see the header"
        exit 99
    fi
done
case "$E" in ''|*[!0-9]*) echo "[SKIP] STAGEF_EPOCH_LENGTH='$E' is not an integer"; exit 99 ;; esac
if [ "$E" != "$E_SHORT" ] && [ "$E" != "$E_PROD" ]; then
    echo "[SKIP] STAGEF_EPOCH_LENGTH=$E — this scenario is laid out for E=$E_SHORT (short run) or E=$E_PROD (production-constant edge run)"
    exit 99
fi
# The two runs' parameters (main's choice of TEST parameters, not plan values):
#   short run:            E 15, BPY 20,      SAFETY grace 15, ERGONOMIC grace 15
#   production-constant:  E 720, BPY 6307200, SAFETY grace 15, ERGONOMIC grace 720
# nodus_witness_vset.c:59 `_Static_assert(DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS
# >= DNAC_EPOCH_LENGTH)` forbids ERGONOMIC 15 at E 720; 720 is the shipped ergonomic
# value (dnac.h:376). The production 17 280 safety grace is NOT exercised.
if [ "$WITH_STORAGE" = 1 ]; then WANT_ERG=15; WANT_BPY=20; else WANT_ERG=720; WANT_BPY="$BPY_PROD"; fi
if [ "$GRACE_ERG" != "$WANT_ERG" ] || [ "$GRACE_SAF" != 15 ]; then
    echo "[SKIP] STAGEF_CC_GRACE_ERGONOMIC=$GRACE_ERG STAGEF_CC_GRACE_SAFETY=$GRACE_SAF — the E=$E run needs SAFETY 15 and"
    echo "       ERGONOMIC $WANT_ERG (build -DDNAC_CHAIN_CONFIG_GRACE_SAFETY_BLOCKS=15$([ "$WITH_STORAGE" = 1 ] && echo ' -DDNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS=15'), both variables exported)"
    exit 99
fi
if [ "${STAGEF_BLOCKS_PER_YEAR:-$BPY_PROD}" != "$WANT_BPY" ]; then
    echo "[SKIP] STAGEF_BLOCKS_PER_YEAR=${STAGEF_BLOCKS_PER_YEAR:-unset} — the E=$E run uses BPY $WANT_BPY"
    exit 99
fi
if [ "$WITH_STORAGE" = 1 ]; then
    if [ ! -s "$CAND/nodus.pk" ] || [ ! -s "$CAND/nodus.sk" ] || [ ! -s "$CAND/nodus.fp" ]; then
        echo "[SKIP] no candidate identity $CAND — the fail-streak crossing registers a storage member that runs no node;"
        echo "       export STAGEF_V2_CANDIDATES=1 BEFORE stagef_up_v2.sh (a genesis-document field: a different chain id)"
        exit 99
    fi
    # settlement amounts are asserted and pool 1 must be funded (stagef_up_v2.sh:668 — without it "no storage
    # settlement can pay anything"; below 2^17 two shares round to 0). The environment variable is NOT read here
    # (round-4 row 7): pool 1 is read from the chain, from v2_treasury, before the storage part (section 3), and
    # an unfunded pool FAILs there.
    # round-4 row 5 (the fetch path): the joiner (node $JOINER) runs with `retain_blocks` so that its block
    # store no longer has segment 1's range when it becomes a holder, which needs a LOWERED evidence window in
    # the hashed genesis document (nodus_cmt_node_check_retain_blocks: retain_blocks must exceed it) — the
    # knobs of test_cmt_prune.sh, exported BEFORE stagef_up_v2.sh.
    CONF_EVB=$(sed -n 's/^evidence_max_age_num_blocks *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
    CONF_EVD=$(sed -n 's/^evidence_max_age_duration_ns *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
    if [ -z "$CONF_EVB" ] || [ -z "$CONF_EVD" ] || [ "$CONF_EVB" -ge 100 ] || [ "$CONF_EVD" -ge $(( (CONF_EVB + 2) * 1000000 )) ]; then
        echo "[SKIP] the genesis document names no lowered evidence window (evidence_max_age_num_blocks='${CONF_EVB:-}' evidence_max_age_duration_ns='${CONF_EVD:-}') —"
        echo "       the fetch path needs node $JOINER to prune: export STAGEF_EVIDENCE_MAX_AGE_BLOCKS=10 STAGEF_EVIDENCE_MAX_AGE_DURATION_NS=1000000 BEFORE stagef_up_v2.sh"
        exit 99
    fi
    RETAIN_J=$(( CONF_EVB + 2 ))
fi
for t in sqlite3 xxd ss openssl; do
    if ! command -v "$t" >/dev/null 2>&1; then
        echo "[SKIP] '$t' is not installed — the HF-9 checks need it"
        exit 99
    fi
done
[ -n "${BASE_DIR:-}" ] && [ -d "$BASE_DIR" ] || die "no active Stage F run (bring one up with stagef_up_v2.sh)"
ref_db0=$(stagef_node_chain_db 1)
[ -n "$ref_db0" ] && [ -s "$ref_db0" ] || die "no chain DB for node1"
# a failed read of an EXISTING database is a FAIL, never "not a Comet cluster"
if ! has_v2=$(sqlite3 "$ref_db0" \
    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='v2_blocks';" 2>&1); then
    die "node1's database $ref_db0 could not be read: $has_v2"
fi
[[ "$has_v2" =~ ^[0-9]+$ ]] || die "node1's database $ref_db0: unexpected answer '$has_v2'"
if [ "$has_v2" = "0" ]; then
    echo "[SKIP] not a Comet cluster — bring it up with stagef_up_v2.sh"
    exit 99
fi
if [ ! -f "$CONF" ]; then
    echo "[SKIP] no $CONF — this scenario needs a stagef_up_v2.sh bring-up"
    exit 99
fi
CONF_E=$(sed -n 's/^epoch_length *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
if [ "$CONF_E" != "$E" ]; then
    echo "[SKIP] the genesis document says epoch_length=${CONF_E:-?}, STAGEF_EPOCH_LENGTH is $E"
    exit 99
fi
# the parameters this run was brought up with, READ from the genesis document and printed
CONF_BPY=$(sed -n 's/^blocks_per_year *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
if [ "$CONF_BPY" != "$WANT_BPY" ]; then
    echo "[SKIP] the genesis document says blocks_per_year=${CONF_BPY:-?}, the E=$E run needs $WANT_BPY"
    exit 99
fi
CONF_INTERVAL=$(sed -n 's/^payout_interval_epochs *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
case "$CONF_INTERVAL" in ''|*[!0-9]*) die "no payout_interval_epochs in $CONF" ;; esac
if [ "$WITH_STORAGE" = 1 ] && [ "$CONF_INTERVAL" -le 1 ]; then
    echo "[SKIP] payout_interval_epochs=$CONF_INTERVAL: every boundary is a payday and empties the accrual the settlement checks read"
    exit 99
fi
is_payday() { [ $(( ($1 / E) % CONF_INTERVAL )) -eq 0 ]; }
mkdir -p "$LOGD"

# ── CAPABILITY GATE (FAIL, not skip) — test_cmt_hf8_gen5.sh's, plus HF-9 ─
bin_version() {            # BIN KIND ("Server" | "CLI") -> X.Y.Z, "" if no banner
    local out re="Nodus $2 v([0-9]+\.[0-9]+\.[0-9]+)"
    out=$("$1" -h 2>&1 || true)
    if [[ "$out" =~ $re ]]; then echo "${BASH_REMATCH[1]}"; fi
}
SRV_VER=$(bin_version "$SRV" Server); CLI_VER=$(bin_version "$CLI" CLI)
[ -n "$SRV_VER" ] && [ -n "$CLI_VER" ] || die "a binary printed no version banner on -h (server '$SRV_VER', cli '$CLI_VER')"
[ "$SRV_VER" = "$CLI_VER" ] || die "the server ($SRV_VER) and the CLI ($CLI_VER) are not one build"
listening() {
    local out
    out=$(ss -ltnH "sport = :$1" 2>/dev/null || true)
    [ -n "$out" ]
}
PROBE_PORT=""
for p in 14991 14992 14993 14994 14995 14996 14997 14998 14999; do
    if ! listening "$p"; then PROBE_PORT="$p"; break; fi
done
[ -n "$PROBE_PORT" ] || die "no free port in 14991..14999 for the usage probe"
usage_out=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose 2>&1 || true)
usage_dec() {              # NAME -> the decimal after "NAME  exactly"
    local v
    v=$(sed -n "s/^  $1  *exactly \\([0-9][0-9]*\\) .*/\\1/p" <<< "$usage_out")
    printf '%s' "${v%%$'\n'*}"
}
D_DEC=$(usage_dec EVM_ACTIVE); D4_DEC=$(usage_dec RULESET_GEN_ROLES)
D5_DEC=$(usage_dec RULESET_GEN_ROOTS); D6_DEC=$(usage_dec RULESET_GEN_TRIE)
[ -n "$D_DEC" ] && [ -n "$D4_DEC" ] && [ -n "$D5_DEC" ] && [ -n "$D6_DEC" ] || {
    printf '%s\n' "$usage_out" >&2
    die "the CLI's chain-config usage does not name 'EVM_ACTIVE', 'RULESET_GEN_ROLES', 'RULESET_GEN_ROOTS' and 'RULESET_GEN_TRIE' with 'exactly <D>' — not an HF-9 build"; }
for v in "$D_DEC" "$D4_DEC" "$D5_DEC" "$D6_DEC"; do
    [ "$v" -gt 0 ] 2>/dev/null || die "a vote literal is not a positive int64 (D '$D_DEC', D4 '$D4_DEC', D5 '$D5_DEC', D6 '$D6_DEC')"
done
D_HEX=$(printf '%016x' "$D_DEC"); D4_HEX=$(printf '%016x' "$D4_DEC")
D5_HEX=$(printf '%016x' "$D5_DEC"); D6_HEX=$(printf '%016x' "$D6_DEC")
# hf9: the binary's own constants, read from its usage — the build must be what the env says
trie_line=$(grep '^  RULESET_GEN_TRIE ' <<< "$usage_out" || true)
copies_line=$(grep '^  STORAGE_COPIES ' <<< "$usage_out" || true)
BIN_SAF=$(sed -n 's/.*vote wait \([0-9][0-9]*\) blocks).*/\1/p' <<< "$trie_line")
BIN_ERG=$(sed -n 's/.*vote wait one epoch, \([0-9][0-9]*\) blocks).*/\1/p' <<< "$copies_line")
BIN_CMIN=$(sed -n 's/^  STORAGE_COPIES  *\[\([0-9][0-9]*\), \([0-9][0-9]*\)\].*/\1/p' <<< "$copies_line")
BIN_CMAX=$(sed -n 's/^  STORAGE_COPIES  *\[\([0-9][0-9]*\), \([0-9][0-9]*\)\].*/\2/p' <<< "$copies_line")
[ -n "$BIN_SAF" ] && [ -n "$BIN_ERG" ] && [ -n "$BIN_CMIN" ] && [ -n "$BIN_CMAX" ] || {
    printf '%s\n' "$usage_out" >&2
    die "the CLI's usage names no 'vote wait N blocks' for RULESET_GEN_TRIE, no 'one epoch, N blocks' or no [min, max] for STORAGE_COPIES — not an HF-9 build"; }
[ "$BIN_SAF" = "$GRACE_SAF" ] || die "the CLI's RULESET_GEN_TRIE vote wait is $BIN_SAF blocks, STAGEF_CC_GRACE_SAFETY is $GRACE_SAF — the build and the environment disagree"
[ "$BIN_ERG" = "$E" ] || die "the CLI's STORAGE_COPIES vote wait is one epoch = $BIN_ERG blocks, STAGEF_EPOCH_LENGTH is $E — the build and the environment disagree"
[ "$BIN_CMIN" = 4 ] && [ "$BIN_CMAX" = 16 ] || die "the CLI's STORAGE_COPIES range is [$BIN_CMIN, $BIN_CMAX], plan D4 says [4, 16]"
# The name-table probe. `chain-config propose` is an OWN-NODE tool since the 4001 change
# (README "nodus-cli in the harness"): in nodus-cli.c the order is :2174-2186 the name table
# ("Unknown param name", return 1), then :2211-2216 the witness-socket lookup ("cannot find this
# node's witness socket", return 1), and only then :2229 "client_connect failed". A call on the
# probe port with a config file that does not exist therefore stops at the socket lookup AFTER the
# name was accepted; a name the table refuses never gets that far. So: the name passed the table
# iff the output holds the socket-lookup line (or, on an older CLI, the connect line) and NOT
# "Unknown param name". --config names a file that cannot exist, so the lookup never depends on
# /etc/nodus.conf of the machine.
for nmv in "RULESET_GEN_TRIE:$D6_DEC" "STORAGE_COPIES:4"; do
    nm="${nmv%%:*}"
    probe=$(timeout 60 "$CLI" -s 127.0.0.1 -p "$PROBE_PORT" chain-config propose \
                --param "$nm" --value "${nmv##*:}" --effective 1 \
                --config "$BASE_DIR/no-such-node-config.json" 2>&1 || true)
    [[ "$probe" != *"Unknown param name"* && \
       ( "$probe" == *"cannot find this node's witness socket"* || "$probe" == *"client_connect failed"* ) ]] || {
        printf '%s\n' "$probe" >&2
        die "the CLI did not pass $nm through its name table (expected the witness-socket lookup or the connect step after it) — not an HF-9 build"; }
done
# hf9: schema S20 on node 1 — the keyed-trie tables, the 24 triggers (names
# v2_trie_l<leg>_<ins|del|upd>, nodus_witness_v2_schema.c), capture = 0
s20=$(sqlite3 -separator '|' "$ref_db0" \
    "SELECT (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN
               ('v2_trie_nodes','v2_trie_roots','v2_trie_dirty','v2_trie_state')),
            (SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'v2_trie_l%'),
            COALESCE((SELECT capture FROM v2_trie_state WHERE id = 1), -1),
            (SELECT COUNT(*) FROM v2_trie_roots);" 2>/dev/null || echo ERR)
[ "$s20" = "4|24|0|0" ] || die "node1's database is not a fresh schema S20 (tables|triggers|capture|leg roots = '$s20', expected 4|24|0|0) — not an HF-9 build, or a chain past the edge"
echo "[ok] capability gate: one build v$SRV_VER; D = 0x$D_HEX, D4 = 0x$D4_HEX, D5 = 0x$D5_HEX, D6 = 0x$D6_HEX; SAFETY wait $BIN_SAF, one epoch $BIN_ERG; schema S20 with the 24 triggers"

# ── script-local helpers (test_cmt_hf8_gen5.sh's, unless "hf9:") ────
db_of()  { stagef_node_chain_db "$1"; }
tip_of() { stagef_cmt_tip "$(db_of "$1")"; }
node_keys() { echo "$(stagef_node_dir "$1")/identity"; }
node_log()  { stagef_node_log "$1"; }
fp_of()  { tr 'A-F' 'a-f' < "$1/nodus.fp" | tr -d '[:space:]'; }   # $1 = identity dir
# dial_for NODE KEYS_DIR — a node refuses a client holding its own key (4001 plan 4.4): the next node
dial_for() {
    if [ "$2" = "$(node_keys "$1")" ]; then echo $(( $1 % N + 1 )); else echo "$1"; fi
}
declare -A FP
for n in $(seq 1 "$N"); do FP[$n]=$(fp_of "$(node_keys "$n")"); done
ALIVE=()                   # hf9: the nodes the cells and the waits compare
for n in $(seq 1 "$N"); do ALIVE+=("$n"); done

# ── TEST-OWNER gate (FAIL — the operator asked for it by setting the keys) ─
if [ -n "$OWN_KEYS" ]; then
    [[ "$OWNER" =~ ^[0-9a-f]{128}$ ]] || die "STAGEF_HF6_OWNER_FP_HEX is not 128 hex characters ('$OWNER')"
    [ -s "$OWN_KEYS/nodus.pk" ] && [ -s "$OWN_KEYS/nodus.sk" ] || die \
        "STAGEF_HF6_OWNER_KEYS=$OWN_KEYS holds no nodus.pk / nodus.sk — make it with stagef_hf6_owner.sh BEFORE the build"
    [ "$(stat -c %s "$OWN_KEYS/nodus.pk")" = 2592 ] || die "$OWN_KEYS/nodus.pk is not 2592 bytes"
    [ "$OWNER" != "$K8_OWNER" ] || die \
        "STAGEF_HF6_OWNER_KEYS is set but STAGEF_HF6_OWNER_FP_HEX is the K8 default — the build must compile the test owner (stagef_hf6_owner.sh prints the flags)"
    own_kfp=$(stagef_sha3_512_hex "$OWN_KEYS/nodus.pk")
    [ "$own_kfp" = "$OWNER" ] || die \
        "SHA3-512($OWN_KEYS/nodus.pk) = ${own_kfp:0:16}… is not STAGEF_HF6_OWNER_FP_HEX ${OWNER:0:16}… — the owner key and the compiled owner must be one identity"
    for n in $(seq 1 "$N"); do
        [ "${FP[$n]}" != "$OWNER" ] || die "the test owner is node$n's own key — it must be a separate identity"
    done
    echo "[ok] TEST-OWNER gate: owner keys $OWN_KEYS, SHA3-512 = ${OWNER:0:16}…"
fi

# hf9: the empty-leg root, plan §4.1 substitution 4: SHA3-512 of the single byte 0x80,
# upper case (sqlite hex())
EMPTY_ROOT=$(printf '\x80' | openssl dgst -sha3-512 -binary | xxd -p -c 256 | tr 'a-f' 'A-F' | tr -d '\n')
[[ "$EMPTY_ROOT" =~ ^[0-9A-F]{128}$ ]] || die "could not compute SHA3-512(0x80) with openssl ('$EMPTY_ROOT')"

node_runs_srv() {
    local pat pid
    pat="-d $(stagef_node_dir "$1")/data"
    for pid in $(pgrep -f -- "$pat" || true); do
        [ "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)" = "$(readlink -f "$SRV")" ] && return 0
    done
    return 1
}

# pump_raw TARGET — the bare pump (the checks below). Every OTHER caller uses pump_to, which serves the queued report
# windows and settlement checks first (round 8, see advance_to): the chain also makes blocks on its own
# (create_empty_blocks, interval 60 s, stagef_env.sh) while a script step waits, so a window can be open at the
# moment a pump starts.
pump_raw() {
    local target="$1" h prc
    h=$(stagef_cmt_pump_to "$(db_of 1)" "$target") && prc=0 || prc=$?
    case "$prc" in
        0) echo "[ok] node1 tip $h >= $target (pumped)" ;;
        1) die "chain STALLED while pumping to $target (tip $h)" ;;
        2) die "a pump spend was not included within 20 heights while pumping to $target (tip $h) — dropped, not delayed" ;;
        *) die "the pump faulted (rc $prc) while pumping to $target (tip $h) — its output is above" ;;
    esac
}

wait_all() {               # every ALIVE node reaches height $1 (progress-bounded)
    local n
    for n in "${ALIVE[@]}"; do
        stagef_cmt_wait_height "$(db_of "$n")" "$1" 3 >/dev/null \
            || die "node$n never reached height $1"
    done
}

# hf9 (T-14): the ONLY way this scenario compares blocks — the 64-byte mode.
# stagef_diff.sh reads all $N nodes, so no node may be down.
diff_full_at() {
    [ "${#ALIVE[@]}" = "$N" ] || die "internal: diff_full_at called while a node is down"
    bash "$S_DIR/stagef_diff.sh" --full --at-height "$1" "$2" || exit 2
}
floor_diff() {             # the race-free floor read, 64-byte mode
    local floor="" h n
    for n in "${ALIVE[@]}"; do
        h=$(tip_of "$n"); [ -n "$h" ] || h=-1
        if [ -z "$floor" ] || [ "$h" -lt "$floor" ]; then floor="$h"; fi
    done
    [ "$floor" -ge 0 ] || die "floor_diff: no node has a block yet"
    diff_full_at "$floor" "$1"
}

cc_row() {
    sqlite3 "$(db_of "$1")" \
        "SELECT new_value || '|' || commit_block || '|' || hex(tx_hash) FROM chain_config_history
          WHERE param_id = $2 AND effective_block = $3;" 2>/dev/null || echo ERR
}

wait_cc_row() {
    local param="$1" eff="$2" val="$3" maxh="$4"
    local h wrc first="" r n rows=""
    h=$(stagef_cmt_wait_row "$(db_of 1)" \
        "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $param
           AND effective_block = $eff AND new_value = $val;" 3 "$maxh") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "chain STALLED waiting for the param-$param row (effective $eff) on node1 (tip $h)" ;;
        *) die "the param-$param row (effective $eff) did not land on node1 within $maxh heights (tip $h)" ;;
    esac
    for n in "${ALIVE[@]}"; do
        stagef_cmt_wait_height "$(db_of "$n")" "$h" 3 >/dev/null \
            || die "node$n never reached height $h (the param-$param row's detection height)"
        r=$(cc_row "$n" "$param" "$eff")
        rows="$rows node$n=$r"
        if [ -z "$first" ]; then first="$r"
        elif [ "$r" != "$first" ]; then die "the param-$param row (effective $eff) DIFFERS across nodes:$rows"; fi
    done
    case "$first" in ""|ERR) die "no param-$param row (effective $eff) readable";; esac
    [ "${first%%|*}" = "$val" ] || die "the param-$param row carries value ${first%%|*}, expected $val"
    CC_CB="${first#*|}"; CC_CB="${CC_CB%%|*}"
    echo "[ok] param-$param row (value $val, effective $eff, commit_block $CC_CB) identical on ${#ALIVE[@]}/$N"
}

cc_guard() {
    local n="$1" t nb try
    for try in 1 2; do
        t=$(tip_of "$n")
        nb=$(( (t / E + 1) * E ))
        if [ $(( t % E )) != 0 ] && [ $(( nb - t )) -ge "$CC_GUARD_GAP" ]; then
            CCG_TIP="$t"; CCG_NB="$nb"
            return 0
        fi
        echo "[info] node$n's tip $t is on or within $CC_GUARD_GAP heights of the epoch boundary $nb — pumping to $(( nb + 1 )) before the proposal (attempt $try)"
        pump_to $(( nb + 1 ))
        wait_all $(( nb + 1 ))
    done
    die "node$n's tip $(tip_of "$n") is still next to an epoch boundary after two guard pumps"
}

cc_guard_after() {
    local t
    t=$(tip_of "$1")
    [ $(( t + 1 )) -lt "$CCG_NB" ] || die \
        "the proposal from node$1 crossed into the epoch boundary $CCG_NB (tip $CCG_TIP -> $t): its approvals may straddle two epochs (the CLI committee/epoch edge, BUGS.md) — the layout broke, not the chain"
}

propose() {
    local name="$1" val="$2" eff="$3" log="$4" prc=0
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$(node_keys 1)" \
        chain-config propose --param "$name" --value "$val" --effective "$eff" > "$log" 2>&1 || prc=$?
    cat "$log"
    cc_guard_after 1
    [ "$prc" = 0 ] || die "chain-config propose $name exited $prc (see $log)"
    grep -q "Round 1: $N/$N approved" "$log" || die "propose $name: round 1 was not $N/$N (see $log)"
    grep -q "proposal accepted" "$log" || die "propose $name did not report acceptance (see $log)"
}

ruleset_info() {
    local n="$1" log rrc=0
    log="$LOGD/ruleset_info_node${n}_$(tip_of "$n").log"
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" ruleset-info > "$log" 2>&1 || rrc=$?
    RI_RC="$rrc"
    RI_OUT=$(cat "$log")
    RI_TIP=$(sed -n 's/^tip=\([0-9]*\) generation=.*/\1/p' "$log")
    RI_GEN=$(sed -n 's/^tip=[0-9]* generation=\([0-9]*\) .*/\1/p' "$log")
    RI_H=$(sed -n 's/^  RULESET_GEN2 height H=\([0-9]*\).*/\1/p' "$log")
    RI_D2=$(sed -n 's/^  node D2=0x\([0-9a-f]*\) .*/\1/p' "$log")
    RI_CLI_D2=$(sed -n 's/^  node D2=0x[0-9a-f]*  this CLI D2=0x\([0-9a-f]*\).*/\1/p' "$log")
}

require_gen() {
    local n="$1" g="$2" hh="$3"
    ruleset_info "$n"
    [ "$RI_RC" = 0 ] || { printf '%s\n' "$RI_OUT" >&2; die "ruleset-info on node$n exited $RI_RC"; }
    [ "$RI_GEN" = "$g" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports generation '$RI_GEN' at tip $RI_TIP, expected $g"; }
    [ "$RI_H" = "$hh" ] || { printf '%s\n' "$RI_OUT" >&2; die "node$n reports RULESET_GEN2 H=$RI_H, expected $hh"; }
    [[ "$RI_OUT" != *MISMATCH* ]] || { printf '%s\n' "$RI_OUT" >&2; die "node$n's D2 differs from the CLI's"; }
    [[ "$RI_OUT" == *"this CLI carries it as compiled generation $g"* ]] || {
        printf '%s\n' "$RI_OUT" >&2; die "the CLI does not carry node$n's tuple as compiled generation $g"; }
}

# an edge crossed on IDLE production (nothing in flight), the full-mode diff AT H-1 / H / H+1
cross_edge() {
    local label="$1" hh="$2" x
    pump_to $(( hh - PUMP_STOP_GAP ))
    wait_all $(( hh + 1 ))
    for x in $(( hh - 1 )) "$hh" $(( hh + 1 )); do diff_full_at "$x" "$label-at-height-$x"; done
}

# hf9: the next height >= $1 that is neither an epoch boundary nor the block after one
# (params 9 / 14 / 18 / 22 / 24 rules: H-1 and, for 18 / 22 / 24, H not a boundary)
clear_of_boundary() {
    local x="$1"
    while [ $(( x % E )) = 0 ] || [ $(( (x - 1) % E )) = 0 ]; do x=$(( x + 1 )); done
    echo "$x"
}

spend_intent() { awk -F= '/^  intent_id=/{print $2; exit}' "$1"; }

claim_leaf() {
    local keys="$1" node="$2" port db fp log h wrc
    port=$(stagef_tcp_port "$(dial_for "$node" "$keys")"); db=$(db_of "$node"); fp=$(fp_of "$keys")
    log="$LOGD/claim_$(basename "$(dirname "$keys")")_via$node.log"
    "$CLI" -s 127.0.0.1 -p "$port" v2-claim --config "$CONF" --db "$db" \
        --keys "$keys" --submit "127.0.0.1:$port" > "$log" 2>&1 \
        || { cat "$log" >&2; die "v2-claim for $keys was refused (see $log)"; }
    h=$(stagef_cmt_wait_row "$db" \
        "SELECT COUNT(*) FROM utxo_set WHERE owner = '$fp'
           AND token_id = zeroblob(64) AND amount > $STAGEF_PUMP_FEE_RAW;") && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "the claimed coin for $keys never appeared (wait rc=$wrc, tip $h)"
    # the identity that CLAIMED (its keys' directory and fingerprint) and the node the CLI dialled are two things (round-4 row 24)
    echo "[ok] claimed the genesis leaf of identity $(basename "$(dirname "$keys")") (fp ${fp:0:16}…) through node$node (tip $h)"
}

# ── hf9: the cell — ONE read snapshot per node, compared across the live nodes ─
# cell_dump NODE "H…" A — BEGIN … COMMIT in one sqlite3 call: a read transaction,
# so every line of the dump is of ONE committed state. Tags:
#   tip|T                         the node's tip
#   gr|H|global_root|block_id|tx  the FULL columns of height H ('-' if absent)
#   txsum|S                       Σ tx_count over heights >= A
#   capture|0/1  dirty|N  leg|i|root   v2_trie_state, v2_trie_dirty, v2_trie_roots
#   src|i|COUNT                   the source table of leg i (leg 3: target CORE = 1, ledger_ids.h)
#   (short run) astate|R|boundary|xfer  basis|fp  assign|k|fp|score|from|to  held|fp|n
#               mepoch|epoch|fp|held_union|n_new  reg|fp|status|exit|fail|grace|reg_h
#               seg|k|published  sets|epoch|count
cell_dump() {
    local n="$1" hl="$2" a="$3" sql h
    sql="BEGIN; SELECT 'tip|' || COALESCE(MAX(global_height), -1) FROM v2_blocks;"
    for h in $hl; do
        sql="$sql SELECT 'gr|$h|' || COALESCE((SELECT hex(global_root) || '|' || hex(block_id) || '|' || tx_count FROM v2_blocks WHERE global_height = $h), '-');"
    done
    sql="$sql SELECT 'txsum|' || COALESCE(SUM(tx_count), 0) FROM v2_blocks WHERE global_height >= $a;"
    sql="$sql SELECT 'capture|' || COALESCE((SELECT capture FROM v2_trie_state WHERE id = 1), '-');"
    sql="$sql SELECT 'dirty|' || COUNT(*) FROM v2_trie_dirty;"
    sql="$sql SELECT 'leg|' || leg || '|' || hex(root) FROM v2_trie_roots ORDER BY leg;"
    sql="$sql SELECT 'src|1|' || COUNT(*) FROM utxo_set;"
    sql="$sql SELECT 'src|2|' || COUNT(*) FROM tokens;"
    sql="$sql SELECT 'src|3|' || COUNT(*) FROM v2_claims_spent WHERE target_domain_id = 1;"
    sql="$sql SELECT 'src|4|' || COUNT(*) FROM v2_names;"
    sql="$sql SELECT 'src|5|' || COUNT(*) FROM v2_storage_nodes;"
    sql="$sql SELECT 'src|6|' || COUNT(*) FROM v2_storage_segments;"
    sql="$sql SELECT 'src|7|' || COUNT(*) FROM validator_set_snapshots;"
    sql="$sql SELECT 'src|8|' || COUNT(*) FROM v2_attendance_epoch;"
    if [ "$WITH_STORAGE" = 1 ]; then
        sql="$sql SELECT 'astate|' || copies || '|' || boundary || '|' || xfer FROM v2_storage_assign_state;"
        sql="$sql SELECT 'basis|' || lower(hex(node_fp)) FROM v2_storage_assign_basis ORDER BY node_fp;"
        sql="$sql SELECT 'assign|' || k || '|' || lower(hex(node_fp)) || '|' || lower(hex(score)) || '|' || from_h || '|' || COALESCE(to_h, '-') FROM v2_storage_assign ORDER BY k, from_h, node_fp;"
        sql="$sql SELECT 'held|' || lower(hex(node_fp)) || '|' || held FROM v2_storage_held ORDER BY node_fp;"
        sql="$sql SELECT 'mepoch|' || epoch_start || '|' || lower(hex(node_fp)) || '|' || held_union || '|' || n_new FROM v2_storage_member_epoch ORDER BY epoch_start, node_fp;"
        sql="$sql SELECT 'reg|' || lower(hex(node_fp)) || '|' || status || '|' || exit_height || '|' || fail_streak || '|' || grace_until || '|' || registered_height FROM v2_storage_nodes ORDER BY node_fp;"
        sql="$sql SELECT 'seg|' || k || '|' || published_height FROM v2_storage_segments ORDER BY k;"
        sql="$sql SELECT 'sets|' || epoch_start || '|' || member_count FROM v2_storage_sets ORDER BY epoch_start;"
    fi
    sql="$sql COMMIT;"
    sqlite3 -cmd '.timeout 5000' "$(db_of "$n")" "$sql" 2>&1
}

CELL=""; CELL_TIP=-1
cell_lines() { sed -n "s/^$1|//p" <<< "$CELL"; }
cell_one()   { cell_lines "$1" | sed -n '1p'; }

# cell_read LABEL "H…" A MIN_TIP — wait until every live node is at MIN_TIP, then read
# every live node's snapshot; the live nodes must agree on the tip (bounded re-read of
# an expected asynchronous condition) and, at one tip, on EVERY byte of the dump.
cell_read() {
    local label="$1" hl="$2" a="$3" min="$4" n d ref="" ref_n="" tips agree
    local lo last_lo=-1 hi since=0 stall=30 t_n
    local -A tip_dump=() tip_node=()
    wait_all "$min"
    # bounded by block distance (the live nodes' highest tip may not pass MIN_TIP + E — a boundary
    # away, where the layout is gone) and by progress (the lowest tip must rise within 30 rounds of 1 s)
    while :; do
        ref=""; agree=1; tips=""; lo=-1; hi=-1
        tip_dump=(); tip_node=()
        for n in "${ALIVE[@]}"; do
            if ! d=$(cell_dump "$n" "$hl" "$a"); then die "$label: node$n's snapshot read failed: $d"; fi
            case "$d" in tip\|*) ;; *) die "$label: node$n's snapshot read failed: $d" ;; esac
            t_n=$(sed -n '1p' <<< "$d" | sed 's/^tip|//')
            tips="$tips node$n=$t_n"
            if [ "$lo" -lt 0 ] || [ "$t_n" -lt "$lo" ]; then lo="$t_n"; fi
            if [ "$t_n" -gt "$hi" ]; then hi="$t_n"; fi
            # every snapshot is compared with the first snapshot OF ITS OWN TIP (round-4 row 14): two nodes
            # at the same tip that differ FAIL at once, whichever node was listed first
            if [ -z "${tip_dump[$t_n]+x}" ]; then tip_dump[$t_n]="$d"; tip_node[$t_n]="$n"
            elif [ "$d" != "${tip_dump[$t_n]}" ]; then
                diff <(printf '%s\n' "${tip_dump[$t_n]}") <(printf '%s\n' "$d") >&2 || true
                die "$label: node$n's snapshot DIFFERS from node${tip_node[$t_n]}'s at the SAME tip $t_n (diff above) — consensus state diverged"
            fi
            if [ -z "$ref" ]; then ref="$d"; ref_n="$n"; fi
        done
        [ "${#tip_dump[@]}" = 1 ] || agree=0
        if [ "$agree" = 1 ]; then
            CELL="$ref"
            CELL_TIP=$(sed -n '1p' <<< "$ref" | sed 's/^tip|//')
            echo "[ok] $label: ${#ALIVE[@]} live nodes agree on every byte of the snapshot at tip $CELL_TIP"
            return 0
        fi
        [ "$hi" -le $(( min + E )) ] || die "$label: the live nodes still disagree on the tip although the highest is $hi, a boundary past $min (last:$tips)"
        if [ "$lo" -gt "$last_lo" ]; then last_lo="$lo"; since=0; else since=$(( since + 1 )); fi
        [ "$since" -lt "$stall" ] || die "$label: the live nodes' lowest tip made no progress in $stall rounds and they never agreed on one tip (last:$tips)"
        sleep 1
    done
}

# hf9: the leg facts of a snapshot. $1 = pre | post
check_legs() {
    local when="$1" label="$2" i root cnt cap dirty nleg
    cap=$(cell_one capture); dirty=$(cell_one dirty)
    nleg=$(cell_lines leg | wc -l)
    for i in 1 2 3 4 5 6 7 8; do
        cnt=$(cell_one "src|$i")
        [[ "$cnt" =~ ^[0-9]+$ ]] || die "$label: the source count of leg $i is '$cnt'"
    done
    if [ "$when" = pre ]; then
        [ "$cap" = 0 ] || die "$label: v2_trie_state.capture reads '$cap' before the edge, expected 0 (plan §5.1: written only by the edge)"
        [ "$dirty" = 0 ] || die "$label: v2_trie_dirty holds $dirty row(s) before the edge, expected 0 (capture = 0: the triggers write nothing)"
        [ "$nleg" = 0 ] || die "$label: v2_trie_roots holds $nleg row(s) before the edge, expected 0"
        return 0
    fi
    [ "$cap" = 1 ] || die "$label: v2_trie_state.capture reads '$cap' after the edge, expected 1"
    [ "$dirty" = 0 ] || die "$label: v2_trie_dirty holds $dirty row(s) at a block's end, expected 0 (plan §5.3 end-of-block assertion)"
    [ "$nleg" = 8 ] || die "$label: v2_trie_roots holds $nleg row(s), expected 8"
    if [ "$WITH_STORAGE" = 0 ]; then
        # the production-constant run registers the four storage members but publishes no segment: leg 5 (the
        # registry) holds exactly those four rows, leg 6 (the segments) is asserted EMPTY with the empty-leg root
        [ "$(cell_one "src|5")" = 4 ] || die "$label: leg 5's source table (v2_storage_nodes) holds $(cell_one "src|5") row(s) in the production-constant run, expected the four registered members"
        [ "$(cell_one "src|6")" = 0 ] || die "$label: leg 6's source table holds $(cell_one "src|6") row(s) in the production-constant run (no segment is reachable)"
        [ "$(cell_one "leg|6")" = "$EMPTY_ROOT" ] || die "$label: leg 6's root is not the empty-leg root in the production-constant run"
    fi
    for i in 1 2 3 4 5 6 7 8; do
        root=$(cell_one "leg|$i"); cnt=$(cell_one "src|$i")
        [[ "$root" =~ ^[0-9A-F]+$ ]] || die "$label: leg $i has no root ('$root')"
        if [ "$cnt" = 0 ]; then
            [ "$root" = "$EMPTY_ROOT" ] || die "$label: leg $i has no source row but its root is ${root:0:16}…, expected the empty-leg root SHA3-512(0x80) = ${EMPTY_ROOT:0:16}… (plan §4.1)"
        else
            [ "$root" != "$EMPTY_ROOT" ] || die "$label: leg $i has $cnt source row(s) but its root is the empty-leg root (the trie holds nothing)"
        fi
    done
    echo "[ok] $label: capture 1, dirty 0, eight leg roots; empty-leg root exactly for the empty source tables ($(for i in 1 2 3 4 5 6 7 8; do printf '%s ' "$(cell_one "src|$i")"; done)rows)"
}

# hf9: populated legs (plan T-13 "populated legs before the edge")
require_populated() {
    local label="$1" i cnt need
    for i in 1 2 3 4 7 8; do
        cnt=$(cell_one "src|$i")
        [ "$cnt" -gt 0 ] || die "$label: leg $i's source table is EMPTY — it must be populated before the edge (the leg would prove nothing)"
    done
    cnt=$(cell_one "src|5")
    [ "$cnt" -gt 0 ] || die "$label: leg 5's source table is EMPTY — the registered storage members are required in both runs"
    if [ "$WITH_STORAGE" = 1 ]; then
        cnt=$(cell_one "src|6")
        [ "$cnt" -gt 0 ] || die "$label: leg 6's source table is EMPTY — a published segment is required in the short run"
    fi
}

# ── hf9: the storage relations (plan §8.4-8.5), every one asserted at a boundary read ──
FPS_SORTED=""              # the fps of the current members, set by members_set
members_set() {            # NODE… -> FPS_SORTED (lower hex, ascending, space-separated)
    local n
    FPS_SORTED=$(for n in "$@"; do printf '%s\n' "${FP[$n]}"; done | LC_ALL=C sort | tr '\n' ' ' | sed 's/ *$//')
}
reg_status() {             # FP -> the registry's status of that fp in the dump ('' if absent)
    cell_lines reg | awk -F'|' -v f="$1" '$1 == f { print $2 }'
}
reg_grace() { cell_lines reg | awk -F'|' -v f="$1" '$1 == f { print $5 }'; }

# check_storage_state B WANT_R LABEL — the invariants at boundary B read at the tip of the dump
check_storage_state() {
    local b="$1" want_r="$2" label="$3" st copies bnd basis elig nb want k cur bad held_calc held_have
    local nact nme
    st=$(cell_one astate)
    [ -n "$st" ] || die "$label: v2_storage_assign_state holds no row"
    IFS='|' read -r copies bnd _ <<< "$st"
    [ "$bnd" = "$b" ] || die "$label: the assignment state is at boundary $bnd, expected $b (the read is past the next boundary, or the state is stale)"
    [ "$copies" = "$want_r" ] || die "$label: v2_storage_assign_state.copies = $copies, expected R = $want_r"
    basis=$(cell_lines basis | tr '\n' ' ' | sed 's/ *$//')
    elig=$(cell_lines reg | awk -F'|' '$2 == 1 && $4 < 3 { printf "%s ", $1 }' | sed 's/ *$//')
    [ "$basis" = "$elig" ] || die "$label: the basis [$basis] is not the registry's ACTIVE members with fail_streak < 3 [$elig] (plan §8.5 steps 1-2)"
    nb=$(cell_lines basis | wc -l)
    [ "$nb" -ge 1 ] || die "$label: the basis is empty"
    want=$(( want_r < nb ? want_r : nb ))
    for k in $(cell_lines seg | awk -F'|' '{ print $1 }'); do
        cur=$(cell_lines assign | awk -F'|' -v k="$k" '$1 == k && $5 == "-"' | wc -l)
        [ "$cur" = "$want" ] || die "$label: segment $k has $cur current assignment row(s), expected min(R=$want_r, eligible=$nb) = $want (plan §8.4 completeness)"
    done
    bad=$(cell_lines assign | awk -F'|' -v basis=" $basis " '$5 == "-" && index(basis, " " $2 " ") == 0 { print $2 }')
    [ -z "$bad" ] || die "$label: a current assignment row names a node outside the basis: $bad"
    held_calc=$(cell_lines assign | awk -F'|' '$5 == "-" { c[$2]++ } END { for (f in c) print f "|" c[f] }' | LC_ALL=C sort)
    held_have=$(cell_lines held | LC_ALL=C sort)
    [ "$held_calc" = "$held_have" ] || die "$label: v2_storage_held [$held_have] is not the per-member count of current rows [$held_calc] (plan §8.4)"
    nact=$(cell_lines reg | awk -F'|' '$2 == 1' | wc -l)
    nme=$(cell_lines mepoch | awk -F'|' -v b="$b" '$1 == b' | wc -l)
    [ "$nme" = "$nact" ] || die "$label: v2_storage_member_epoch has $nme row(s) at $b, expected one per ACTIVE member = $nact"
    # K9: n_new > 0 raises grace_until to at least B + n_new × E
    while IFS='|' read -r _ fp _ nn; do
        [ "$nn" -gt 0 ] || continue
        [ "$(reg_grace "$fp")" -ge $(( b + nn * E )) ] || die "$label: ${fp:0:16}… has n_new $nn at $b but grace_until $(reg_grace "$fp") < $(( b + nn * E )) (K9)"
    done < <(cell_lines mepoch | awk -F'|' -v b="$b" '$1 == b')
    echo "[ok] $label: boundary $b, R = $want_r, |basis| = $nb, every segment has $want current rows, held = rows, member_epoch rows = $nact, grace >= boundary + n_new x E"
}
# ── hf9: the EXACT recurrences (round-4 rows 3, 8, 9) ──────────────────────────────────────────────
# derive_union B — held_union and n_new of every member_epoch row at B, derived from the stored ASSIGNMENT
# relation alone (rows current AND ended, the segments' publication heights, the members), by the plan's
# own definition (docs/plans/approved/2026-11-04-hf9.md :299-302 §8.5 step 5): for the members m of set(B)
# and the segments k published <= B - E (K9a cutoff), prev(k) = the rows current at B - E (from_h <= B - E
# and not ended at or before it), new(k) = the rows current after B;
#   ended(m) = |{k : m in prev(k) \ new(k)}|    n_new(m) = |{k : m in new(k) \ prev(k)}|
#   held(m) = the current rows of m (every k, the ones published at B included)
#   held_union(m, B) = held(m) + ended(m)
# Valid for B > B1 only: at B1 prev(k) is the XOR relation of set(H2), which no table holds (it is not
# recomputed here — see HOW IT CAN LIE). Output: "fp|held_union|n_new", sorted.
derive_union() {           # B
    { cell_lines assign | sed 's/^/A|/'; cell_lines seg | sed 's/^/S|/'; cell_lines mepoch | sed 's/^/M|/'; } |
    awk -F'|' -v b="$1" -v e="$E" '
        $1 == "S" { pub[$2] = $3 + 0; next }
        $1 == "A" {
            from = $5 + 0; to = $6
            if (from <= b - e && (to == "-" || to + 0 > b - e)) prev[$2 SUBSEP $3] = 1
            if (from <= b && (to == "-" || to + 0 > b)) { cur[$2 SUBSEP $3] = 1; held[$3]++ }
            next
        }
        $1 == "M" && $2 + 0 == b { mem[$3] = 1; next }
        END {
            for (key in prev) {
                split(key, a, SUBSEP); k = a[1]; f = a[2]
                if (!(f in mem) || pub[k] > b - e) continue
                if (!(key in cur)) ended[f]++
            }
            for (key in cur) {
                split(key, a, SUBSEP); k = a[1]; f = a[2]
                if (!(f in mem) || pub[k] > b - e) continue
                if (!(key in prev)) nn[f]++
            }
            for (f in mem) print f "|" (held[f] + ended[f]) "|" (nn[f] + 0)
        }' | LC_ALL=C sort
}
declare -A GR_PREV FS_PREV     # the registry values read at the previous boundary cell (absent = 0, the registration value)
# fs_next OLD HAD_ELIGIBLE OK -> the new counter — nodus_storage_fail_streak_next (nodus_witness_v2_storage.c:1330-1339)
fs_next() {
    local old="$1" had="$2" ok="$3"
    if [ "$had" = 1 ] && [ "$ok" = 1 ]; then echo 0; return; fi          # K5a: even at >= 3
    if [ "$old" -ge 3 ]; then                                            # skipped (K5)
        if [ "$old" -ge 14 ]; then echo 0; else echo $(( old + 1 )); fi
        return
    fi
    if [ "$had" = 0 ]; then echo "$old"; else echo $(( old + 1 )); fi
}
# check_transition_exact B LABEL — at boundary B, from the previous cell's registry values:
#  (1) B > B1: held_union / n_new of every member_epoch row = derive_union (stored values are not their own oracle)
#  (2) grace_until of every member_epoch row = max(previous, B + n_new x E) when n_new > 0, UNCHANGED when 0
#      (nodus_storage_grace_next, nodus_witness_v2_storage.c:892-901)
#  (3) fail_streak of EVERY registry row = the source recurrence over the settled epoch H = B - 2E, whose
#      grace / verdict / weight were READ in its report window (epoch_service_read): a member of set(H) in
#      grace or NO_EVIDENCE is unchanged, else fail_streak_next(old, weight > 0, verdict = OK); a registry
#      row that was not in set(H) is unchanged (nodus_witness_v2_storage.c:1704-1713)
check_transition_exact() {
    local b="$1" label="$2" fp hu nn exp have want h ev hh had ok old
    if [ "$b" -gt "$B1" ]; then
        exp=$(derive_union "$b")
        have=$(cell_lines mepoch | awk -F'|' -v b="$b" '$1 == b { print $2 "|" $3 "|" $4 }' | LC_ALL=C sort)
        [ "$exp" = "$have" ] || { diff <(printf '%s\n' "$exp") <(printf '%s\n' "$have") >&2 || true
            die "$label: v2_storage_member_epoch at $b (right) differs from held_union / n_new derived from the assignment relation (left)"; }
        while IFS='|' read -r fp hu nn; do [ -z "$fp" ] || DER_HU["$b|$fp"]="$hu|$nn"; done <<< "$exp"
    fi
    while IFS='|' read -r _ fp hu nn; do
        [ -n "$fp" ] || continue
        old="${GR_PREV[$fp]:-0}"
        if [ "$nn" -gt 0 ]; then want=$(( b + nn * E )); [ "$want" -ge "$old" ] || want="$old"; else want="$old"; fi
        [ "$(reg_grace "$fp")" = "$want" ] || die "$label: ${fp:0:16}… grace_until is $(reg_grace "$fp"), the recurrence max(previous $old, $b + $nn x $E) (unchanged for n_new 0) gives $want (K9)"
    done < <(cell_lines mepoch | awk -F'|' -v b="$b" '$1 == b { print $1 "|" $2 "|" $3 "|" $4 }')
    h=$(( b - 2 * E ))
    if [ "$h" -ge "$E" ]; then
        [ -n "${EPM[$h]+x}" ] || die "$label: internal — the report window of epoch $h (settled at $b) was never read — $MSG_LAYOUT"
        for fp in $(cell_lines reg | awk -F'|' '{ print $1 }'); do
            old="${FS_PREV[$fp]:-0}"
            want="$old"
            case " ${EPM[$h]} " in
                *" $fp "*)
                    ev="${EPV["$h|$fp"]}"
                    case "$ev" in
                        grace) want="$old" ;;
                        ok)    want=$(fs_next "$old" 1 1) ;;
                        dead)  want=$(fs_next "$old" 1 0) ;;
                        none)  want=$(fs_next "$old" 0 0) ;;
                        *)     die "$label: internal — epoch $h verdict of ${fp:0:16}… is '$ev'" ;;
                    esac ;;
            esac
            [ "$(reg_fs "$fp")" = "$want" ] || die "$label: ${fp:0:16}… fail_streak is $(reg_fs "$fp"), the settlement of epoch $h (verdict '${EPV["$h|$fp"]:-not in set($h)}', previous $old) gives exactly $want"
        done
    fi
    while IFS='|' read -r fp _ _ fs g _; do
        [ -n "$fp" ] || continue
        GR_PREV[$fp]="$g"; FS_PREV[$fp]="$fs"
    done < <(cell_lines reg)
    echo "[ok] $label: grace_until and fail_streak equal the source recurrences exactly$([ "$b" -gt "$B1" ] && echo ", held_union / n_new equal the values derived from the assignment relation")"
}
n_new_sum()  { cell_lines mepoch | awk -F'|' -v b="$1" '$1 == b { s += $4 } END { print s + 0 }'; }
rows_from()  { cell_lines assign | awk -F'|' -v b="$1" '$4 == b && $5 == "-"' | wc -l; }
rows_ended() { cell_lines assign | awk -F'|' -v b="$1" '$5 == b' | wc -l; }
cur_holders_of() {         # K -> the nodes (indexes) holding segment K now
    local f n
    for f in $(cell_lines assign | awk -F'|' -v k="$1" '$1 == k && $5 == "-" { print $2 }'); do
        for n in $(seq 1 "$N"); do [ "${FP[$n]}" = "$f" ] && echo "$n"; done
    done
}

# hf9 (T-16): segment files of the holder runtime (nodus_witness_storage_segment.h:
# seg-<k>.ok is the completeness marker; the segment directory is data/segments)
seg_file() { echo "$(stagef_node_dir "$1")/data/segments/seg-$2.ok"; }
# The two waits are bounded by BLOCK DISTANCE (node 1's tip reaching UNTIL_TIP) and by PROGRESS
# (no tip increase for 3 CreateEmptyBlocks intervals = a stall, stagef_cmt_wait_height's rule);
# rc 0 condition reached, 1 deadline height reached, 2 stalled.
file_wait_polls() { echo $(( 3 * STAGEF_CMT_EMPTY_INTERVAL_MS / 1000 / 2 )); }   # 2 s polls
#   The tip is read AFTER the file observation (round 10, row 6; round 4 read it before) and the observation is
#   accepted only when that tip is below the deadline (UNTIL_TIP is exclusive): the tip is monotonic, so a tip read
#   after the observation bounds the observation's own tip; a file seen while the chain crossed the deadline is
#   a late file, never an accepted one. wait_seg_gone is the same for a file that disappeared.
wait_seg_file() {          # NODE K UNTIL_TIP
    local f t seen last=-1 since=0 stall
    f=$(seg_file "$1" "$2"); stall=$(file_wait_polls)
    while :; do
        service_reads; service_posts      # round 8: a wait that does not pump still serves the queued windows (the chain moves on its own)
        # round 10 (row 6): the observation first, THEN the tip — the tip is monotonic, so a tip read after the
        # observation bounds the observation's own tip; a file seen while the chain crossed the deadline is late
        seen=0; if [ -f "$f" ]; then seen=1; fi
        t=$(tip_of 1)
        if [ "$seen" = 1 ]; then
            if [ "$t" -lt "$3" ]; then return 0; fi
            return 1
        fi
        if [ "$t" -ge "$3" ]; then return 1; fi
        if [ "$t" -gt "$last" ]; then last="$t"; since=0; else since=$(( since + 1 )); fi
        if [ "$since" -ge "$stall" ]; then echo "[FAIL] the chain stalled at tip $t while waiting for $f" >&2; return 2; fi
        sleep 2
    done
}
# The OVERLAP rule is asserted from the holder runtime's own epoch-stamped line, never from "the file
# at tip X" (a pump overshoots a height by a block, and the file is legitimately gone from the epoch
# H = B + E on). nodus_witness_storage_holder.c:283-288 logs, per deletion,
#   "segment <k> deleted: no longer a holder and the overlap epoch has passed (H=<H>)"
# with H = floor(tip / E) x E of the node's own tip at the sweep; a segment is deleted iff this node is no
# holder in the epoch H nor (for segments published <= H - E) in H - E. So the file is kept through the
# epochs B .. B + E - 1 exactly when the deletion line's H is = B + E (round 10: exactly, see assert_deleted_at). The node log is the witness log
# (stagef_node_log) — appended, never truncated, for a node that is not wiped (node 3 is no holder).
del_count() { grep -c "segment $2 deleted: no longer a holder" "$(node_log "$1")" || true; }   # NODE K
del_h() {                  # NODE K INDEX(1-based) -> the H of that deletion line
    grep "segment $2 deleted: no longer a holder" "$(node_log "$1")" | sed -n "${3}p" | sed 's/.*(H=\([0-9]*\)).*/\1/'
}
#   The holder removes seg-<k>.ok FIRST and logs only after nodus_seg_delete returned (segment.c:1193-1205 unlinks
#   the marker, five more files and syncs the directory; holder.c:283-285 logs afterwards), so a file seen gone
#   does not yet mean the line is written: assert_deleted_at WAITS for it, bounded by block distance (the tip may
#   not pass MIN_H + E) and by progress (no tip increase for 3 CreateEmptyBlocks intervals), and FAILs if it never
#   comes (round-4 row 12).
assert_deleted_at() {      # LABEL NODE K COUNT_BEFORE MIN_H — a NEW deletion line since COUNT_BEFORE, with H = MIN_H (= B + E) exactly
    local label="$1" n="$2" k="$3" c0="$4" minh="$5" c1 h t last=-1 since=0 stall
    stall=$(file_wait_polls)
    while :; do
        service_reads; service_posts      # round 8: serve the queued windows while waiting
        c1=$(del_count "$n" "$k")
        [ "$c1" -le "$c0" ] || break
        t=$(tip_of 1)
        [ "$t" -lt $(( minh + E )) ] || die "$label: node$n logged no new 'segment $k deleted' line by tip $t (had $c0, has $c1; waited to MIN_H + E = $(( minh + E )))"
        if [ "$t" -gt "$last" ]; then last="$t"; since=0; else since=$(( since + 1 )); fi
        [ "$since" -lt "$stall" ] || die "$label: the chain stalled at tip $t while waiting for node$n's 'segment $k deleted' line"
        sleep 2
    done
    h=$(del_h "$n" "$k" $(( c0 + 1 )))
    [[ "$h" =~ ^[0-9]+$ ]] || die "$label: could not read the H of node$n's deletion line"
    # ROUND 10 (row 10): the deletion line's H is EXACTLY B + E. The holder ticks every 200 ms (holder.h:110
    # NODUS_STHOLD_TICK_MS) and runs `assign` at an epoch change (holder.c:646-661), which calls the sweep
    # nodus_witness_sthold_gc (holder.c:369) with the epoch H of the tick; a segment is deleted when this node is a holder
    # in neither H nor H - E (holder.c:172-228 / :241-290), and the node's rows ended at B, so the first sweep that can
    # delete runs in epoch B + E and logs H = B + E. An H below it is a deletion inside the overlap epoch, one above it
    # a sweep that missed epoch B + E; both FAIL.
    [ "$h" -eq "$minh" ] || die "$label: node$n deleted segment $k at its epoch H=$h, expected exactly H=$minh (the first sweep after the overlap epoch: holder.c:646-661, :369)"
    echo "[ok] $label: node$n logged the deletion of segment $k at its epoch H=$h = B + E exactly: no sweep deleted it earlier and the first sweep of epoch $minh did (the deletion HEIGHT; that the file existed in the overlap epoch is asserted separately from the file itself)"
}
# The RETENTION evidence (round-4 row 11): seg-<k>.ok of a node that is no longer a holder, seen to EXIST at a
# tip inside the overlap epoch. The tip is read before and after the file test and BOTH must lie in [B, B + E - 1]:
# nothing deletes the file before the sweep of epoch H = B + E (holder.c:263-285), so the file seen at a tip in
# that range was kept through the overlap. A tip outside the range is a layout failure (a false RED).
assert_file_in_overlap() { # LABEL NODE K B
    local label="$1" n="$2" k="$3" b="$4" t0 t1
    t0=$(tip_of 1)
    [ -f "$(seg_file "$n" "$k")" ] || die "$label: node$n's $(seg_file "$n" "$k") does not exist at tip $t0 inside the overlap epoch [$b, $(( b + E - 1 ))] — the file was not retained"
    t1=$(tip_of 1)
    { [ "$t0" -ge "$b" ] && [ "$t1" -le $(( b + E - 1 )) ]; } || die "$label: the overlap-epoch file check ran at tips $t0 .. $t1, outside [$b, $(( b + E - 1 ))] — $MSG_LAYOUT"
    echo "[ok] $label: node$n still has seg-$k.ok at tips $t0 .. $t1, inside the overlap epoch [$b, $(( b + E - 1 ))] (retention evidence: the file itself)"
}
wait_seg_gone() {          # NODE K UNTIL_TIP
    local f t seen last=-1 since=0 stall
    f=$(seg_file "$1" "$2"); stall=$(file_wait_polls)
    while :; do
        service_reads; service_posts      # round 8: serve the queued windows while waiting
        seen=0; if [ ! -e "$f" ]; then seen=1; fi      # round 10 (row 6): the observation first, then the tip
        t=$(tip_of 1)
        if [ "$seen" = 1 ]; then
            if [ "$t" -lt "$3" ]; then return 0; fi
            return 1
        fi
        if [ "$t" -ge "$3" ]; then return 1; fi
        if [ "$t" -gt "$last" ]; then last="$t"; since=0; else since=$(( since + 1 )); fi
        if [ "$since" -ge "$stall" ]; then echo "[FAIL] the chain stalled at tip $t while waiting for $f to go" >&2; return 2; fi
        sleep 2
    done
}
require_holder_files() {   # LABEL BOUNDARY — every current holder of segment 1 has seg-1.ok before the next boundary
    local label="$1" b="$2" n
    for n in $(cur_holders_of 1); do
        wait_seg_file "$n" 1 $(( b + E )) || die "$label: node$n is a current holder of segment 1 at $b but $(seg_file "$n" 1) did not appear before the next boundary (the holder runtime did not export / fetch it)"
    done
    echo "[ok] $label: every current holder of segment 1 ($(cur_holders_of 1 | tr '\n' ' ')) has the marker file seg-1.ok at a tip below the next boundary $(( b + E )) (marker PRESENT only: its content, index and data are not validated here — the segment code validates them when it serves, segment.c:1004-1015, and the reporter answers from the block store first, reporter.c:281; the holder's job_finish / mark_held (holder.c:328-331, :488-499) prints no line of its own for a validated marker, so none is asserted — so for holders that export from an archive store the file is not exercised by their probes)"
}

# bs_base NODE — the lowest height with a `P:` row in the node's block store (cmt_blockstore, the key shape
# test_cmt_prune.sh reads); -1 when it holds none
bs_base() {
    sqlite3 -cmd '.timeout 10000' "$(db_of "$1")" \
        "SELECT COALESCE(MIN(CAST(substr(CAST(key AS TEXT), 3) AS INTEGER)), -1) FROM cmt_blockstore WHERE substr(CAST(key AS TEXT), 1, 2) = 'P:';"
}
# bs_height NODE — the highest height with a `P:` row in the node's block store; -1 when it holds none
bs_height() {
    sqlite3 -cmd '.timeout 10000' "$(db_of "$1")" \
        "SELECT COALESCE(MAX(CAST(substr(CAST(key AS TEXT), 3) AS INTEGER)), -1) FROM cmt_blockstore WHERE substr(CAST(key AS TEXT), 1, 2) = 'P:';"
}
# assert_members_hold_range LABEL K B — the K9a premise (decision 2026-10-05-storage-reward-is-for-archive.md: "A
# segment published at boundary H is NOT counted (every node holds the last 7 paydays in its block store)"), read
# from the stores BEFORE the publication boundary B of segment K (round 6): every registered storage member (ACTIVE or
# EXITING, the statuses role_prune.c:92-113 reads) that runs a node has base <= (K-1) x P + 1 and height >= K x P + 1 —
# nodus_seg_store_has (segment_export.c:48-55) — so none is probed at B on a segment it would still have to fetch. A
# member that runs no node (the candidate) has no store and is not read.
#
# THE READ TIP (round 9). The premise needs height >= K x P + 1, so the read cannot be earlier than the tip K x P + 1 =
# LO; it must be before B = K x P + 2E, so the window is [LO, B - 1], 2E - 1 heights wide (29 at E 15) — NOT the single
# tip B - 1 (run 10 read from the tip 750 = B after a pump landed on B - 1 and the chain made B on its own: after a block
# that changed the app hash the next block is proposed without waiting for transactions, cometbft v0.38.26
# consensus/state.go:1101 and :1113-1127 / shared/dnac/cmt_cs.c:1957-2010, timeout_commit 4 s, stagef_env.sh:1027-1030).
# read_k9a_premise therefore reads at the EARLIEST tip, LO: a pump to LO is ESTIMATED to land at most PUMP_LAND_MAX above LO (an inference, see below) — a spend
# submitted at a tip < LO is included within 20 heights (stagef_cmt_wait_row's budget, `-gt $max_heights`, default 20,
# stagef_env.sh:1166, :1186; rc 2 otherwise) plus a poll of 5 s (:1167) that may see one more block (inference: one
# block per timeout_commit 4 s) — and the chain's own blocks during the read are few (seconds against a 60 s idle
# interval; a proof block after the last spend). Distance left to B - 1 = 2E - 1 - PUMP_LAND_MAX heights (7 at E 15), and the
# tip is read BEFORE and AFTER the store reads: both must be below B, else a named layout FAIL. WHAT THE RESULT RELIES ON
# between the read tip and the holder's export / fetch decision after B: the unpublished-period guard of the retain
# height (nodus_witness_role_prune.c:51-69: r = min(tip - N + 1, keep_from_segment, keep_from_unpublished) for a storage
# member; :318-326: keep_from_unpublished = seg_first(maxk + 1) = maxk x P + 1 = (K-1) x P + 1 = the first height of
# segment K while K - 1 is the highest published) — no registered storage member's store is pruned above (K-1) x P + 1
# until K is published; at B the cache is refilled for (H, maxk = K) and keep_from_segment keeps the first incomplete
# must-hold segment's first height for a member that holds K. A member that does NOT hold K is not probed on it
# (eligible segments = its own rows) and may prune it.
# (Round 10, row 7: PUMP_LAND_MAX is an INFERENCE, not a bound. stagef_cmt_wait_row returns 0 as soon as the row is
# seen, BEFORE the height budget test (stagef_env.sh:1176-1180 against :1186), and its start_h is read after the
# CLI submit returned, so blocks made during the submit are not counted. 22 only sizes the window; what makes the
# read sound are the fail-closed tip guards in assert_members_hold_range — the tip must be in [kP+1, B-1] before AND
# after the store reads, else a named layout FAIL.)
#
# THE MEMBERS (round 10, row 9): the registered storage members that run a node and were read at the premise tip are
# recorded (PREMISE_SET); at the publication boundary check_premise_members requires every such member present at
# B to be one of them — a member that registered between the read and B (the guard role_prune.c:57 applies only
# `if (in->is_storage)`, so its store was not protected) is a named layout FAIL, never an unread store.
declare -A PREMISE_SET
check_premise_members() {  # LABEL K — uses the cell just read at the publication boundary
    local label="$1" k="$2" fp st n
    [ -n "${PREMISE_SET[$k]+x}" ] || die "$label: the K9a premise of segment $k was never read — $MSG_LAYOUT"
    while IFS='|' read -r fp st _; do
        [ "$st" = 1 ] || [ "$st" = 2 ] || continue
        n=$(fp_node "$fp"); [ -n "$n" ] || continue
        case " ${ALIVE[*]} " in *" $n "*) ;; *) continue ;; esac
        case "${PREMISE_SET[$k]}" in *" $fp "*) ;; *) die "$label: node$n (${fp:0:16}…) is a registered storage member at the publication boundary of segment $k but its block store was not read at the premise tip (${PREMISE_SET[$k]}) — it registered in between; its range before registration is not established (K9a premise) — $MSG_LAYOUT" ;; esac
    done < <(cell_lines reg)
    echo "[ok] $label: every registered storage member that runs a node at the publication of segment $k is one whose block store was read at the premise tip"
}
PUMP_LAND_MAX=22
read_k9a_premise() {       # LABEL K B — pump to LO if the tip is below it, then assert_members_hold_range
    local label="$1" k="$2" b="$3" lo
    lo=$(( k * P + 1 ))
    [ $(( b - 1 - (lo + PUMP_LAND_MAX) )) -ge 1 ] || die "$label: the window [$lo, $(( b - 1 ))] is not wider than the pump's landing estimate $PUMP_LAND_MAX (an inference, not a bound) — $MSG_LAYOUT"
    if [ "$(tip_of 1)" -lt "$lo" ]; then pump_to "$lo"; fi
    wait_all "$lo"
    assert_members_hold_range "$label" "$k" "$b"
}
assert_members_hold_range() {
    local label="$1" k="$2" b="$3" fp n base hgt first last cnt=0 t0 t1 set_read=""
    first=$(( (k - 1) * P + 1 )); last=$(( k * P + 1 ))
    t0=$(tip_of 1)
    { [ "$t0" -ge "$last" ] && [ "$t0" -lt "$b" ]; } || die "$label: the premise read starts at tip $t0, outside [$last, $(( b - 1 ))] (segment $k's last height + 1 .. one block before its publication boundary $b) — $MSG_LAYOUT"
    for fp in $(sqlite3 -cmd '.timeout 5000' "$(db_of 1)" "SELECT lower(hex(node_fp)) FROM v2_storage_nodes WHERE status IN (1, 2) ORDER BY node_fp;"); do
        n=$(fp_node "$fp"); [ -n "$n" ] || continue
        case " ${ALIVE[*]} " in *" $n "*) ;; *) continue ;; esac
        base=$(bs_base "$n"); hgt=$(bs_height "$n")
        { [[ "$base" =~ ^[0-9]+$ ]] && [[ "$hgt" =~ ^[0-9]+$ ]]; } || die "$label: node$n's block-store base / height are unreadable ('$base' / '$hgt')"
        { [ "$base" -le "$first" ] && [ "$hgt" -ge "$last" ]; } || die "$label: node$n is a storage member but its block store covers $base .. $hgt, not segment $k's whole range ($first .. $(( k * P ))) with height >= $last — it would be probed at $b on a segment it must still fetch (K9a premise broken) — $MSG_LAYOUT"
        cnt=$(( cnt + 1 )); set_read="$set_read $fp"
    done
    PREMISE_SET[$k]="$set_read "
    [ "$cnt" -ge 1 ] || die "$label: no storage member's block store could be read"
    t1=$(tip_of 1)
    [ "$t1" -lt "$b" ] || die "$label: the chain reached tip $t1, the publication boundary $b of segment $k, while the stores were read (the read started at tip $t0) — the premise cannot be established before it — $MSG_LAYOUT"
    echo "[ok] $label: read at tips $t0 .. $t1 (before the publication of segment $k at $b, $(( b - 1 - t1 )) block(s) to spare): the block stores of all $cnt registered storage members that run a node hold its whole range ($first .. $(( k * P )), height >= $last)"
}
reg_fs()   { cell_lines reg | awk -F'|' -v f="$1" '$1 == f { print $4 }'; }
in_basis() { [ -n "$(cell_lines basis | awk -v f="$1" '$0 == f')" ]; }
cur_rows_of() { cell_lines assign | awk -F'|' -v f="$1" '$2 == f && $5 == "-"' | wc -l; }

declare -A SETTLE_EXP SETTLE_POOL SETTLE_ACC NEWH_AT ZERO_AT   # per epoch H: see epoch_service
PEND_READ=""               # epochs whose reports are still to be read (their window not served yet)
PEND_POST=""               # epochs read, whose settlement (at H + 2E) is still to be checked
DEAD_FP=""                 # the candidate (it runs no node): its bit must be 0 wherever it is probed

# hf9: pump to the boundary (NOT past it: no pump spend after the boundary block), service the
# report windows passed on the way, read the cell, check the generic storage invariants, and
# register the boundary's epoch for its reports and its settlement. Per plan T-13 the leg-root
# snapshot is "of the boundary state" only to the extent that no envelope came after it: the tx
# count over (B, T] is printed, and a snapshot with envelopes after B is said to be of a LATER state.
boundary_cell() {          # LABEL BOUNDARY R
    advance_to "$2"
    cell_read "$1" "$2" "$(( $2 + 1 ))" "$2"
    local since
    since=$(cell_one txsum)
    if [ "$since" = 0 ]; then
        echo "[ok] $1: no envelope after the boundary block up to tip $CELL_TIP — the snapshot is of the boundary state (claims are counted by no tx_count; none was submitted)"
    else
        echo "[info] $1: $since envelope(s) after the boundary block up to tip $CELL_TIP — the leg roots read are of a LATER state (tip $CELL_TIP), NOT of height $2. At $2 only the full global_root is compared 7/7 (diff --full), which binds the eight leg roots through the composition chain (plan §10.3, docs/plans/approved/2026-11-04-hf9.md:396-397); a per-height leg-root comparison at this boundary is NOT covered (v2_trie_roots keeps the latest root of each leg only — plan §16 DF-3, :614)"
    fi
    check_legs post "$1"
    check_storage_state "$2" "$3" "$1"
    check_transition_exact "$2" "$1"
    # the publication boundary of segment k = (b - 2E) / P (k >= 2 here; segment 1 is checked in section 3): the
    # members present now must be the ones whose stores were read at the premise tip (round 10, row 9)
    if [ "$2" -gt $(( 2 * E )) ] && [ $(( ($2 - 2 * E) % P )) = 0 ] && [ $(( ($2 - 2 * E) / P )) -ge 2 ]; then
        check_premise_members "$1" $(( ($2 - 2 * E) / P ))
    fi
    case " $PEND_READ $PEND_POST " in *" $2 "*) ;; *) PEND_READ="$PEND_READ $2" ;; esac
    service_posts
    # the boundary kP (k >= 2) is the first in which the premise of segment k's publication at kP + 2E can be read
    # (height >= kP + 1, round 9): read it now, at the earliest tip, two epochs before the publication, instead of one
    # block before it (the single-block window of rounds 6-8). Segment 1 is read in section 3 the same way.
    if [ "$WITH_STORAGE" = 1 ] && [ "$2" -gt 0 ] && [ $(( $2 % P )) = 0 ] && [ $(( $2 / P )) -ge 2 ]; then
        read_k9a_premise "$1 (K9a premise of segment $(( $2 / P )))" $(( $2 / P )) $(( $2 + 2 * E ))
    fi
}

# hf9 (T-16, the bits): what the stored reports say. Source: nodus_witness.h
# v2_storage_reports ("bitmap … LSB-first bit i = member i", seat = index in
# snapshot(H)) and v2_storage_set_members ("node_fp ASC is the bitmap order");
# the reporter sets bit i only when its probe of member i answered OK
# (nodus_witness_storage_reporter.c: STP_NOPROBE — itself, no eligible segment,
# in grace — and a probe that fails or is never reachable are bit 0);
# a member is eligible at H when it is not in grace (H >= grace_until) and has
# assignment rows at H or at H-E (nodus_witness_v2_storage.c
# nodus_witness_storage_eligible_segments / nodus_witness_storage_member_ks).
# The reports of epoch H are committed in the window (H+E, H+E+floor(E/2)] and
# pruned at the settlement boundary H+2E (nodus_witness_storage_probe.h, and the
# reads of test_storage_archive.sh step 8) — so they are read at a tip in
# [H+E+floor(E/2), H+2E-1]. report_bits sets RB_N (reports) and RB_Y (reports
# whose bit of member FP is 1); every live node must return the same rows.
#
# THE VERDICT (nodus_witness_v2_storage.c:1359-1397 nodus_storage_member_verdict): the seats that
# reported count by POWER, except a seat whose owner equals the member's owner or whose key equals
# the member's fp (F2); I = the counted reporting power, Y = the counted power with bit 1;
# 2·I <= P_total -> NO_EVIDENCE, else 3·Y > 2·I -> OK, else NOT_OK. Round 10: epoch_reads computes I and Y
# EXACTLY with those exclusions from snapshot(H)'s seat keys and owners (see (2) below); all seats have equal
# power (READ from snapshot(H) — not assumed) so power = seat count and P_total = $N. NO_EVIDENCE is
# "undetermined" and FAILs the scenario (it never guesses a verdict).
# The verdict below is the source verdict under these prerequisites, read from the chain (round-4
# row 2, corrected in round 5) — not assumed:
#  (1) EQUAL SEAT POWER, read from what the source reads: snapshot(H) = validator_set_snapshots.snapshot_blob of
#      epoch_start H (nodus_witness_v2_epoch_authority_for_epoch, nodus_witness_v2_epoch.c:2421-2465, "the ONLY
#      source … nothing in this function reads the `validators` table"), whose entries nodus_witness_vset_powers
#      turns into power (nodus_witness_vset.c:952-1011; used by nodus_witness_v2_storage.c:1519-1551). The count
#      must be N and every entry's total_stake equal and non-zero, identical on every live node. Equal total_stake
#      gives equal power in both rulesets: ruleset 1 = total_stake / DNAC_DECIMAL_UNIT per entry; ruleset 2 =
#      dna_power_cap_counted over those whole-coin powers, whose output is min(p_i, cap) with ONE cap for all
#      entries (shared/dnac/power_cap.c:87; power_cap.h "equal p always yield equal counted"). The
#      generation-4 edge's self-delegations (nodus_witness_v2_migrate.c:681-708) are in the `delegations`
#      table and in total_stake; they are NOT assumed absent, and the `validators` table and the `delegations`
#      count are not read for this.
#      Layout (shared/dnac/vset_wire.h:31-39, :78-84, :141-143): header 78 bytes = epoch u64 + active_count u16 +
#      selection_ruleset u32 BE + 64 seed; ruleset 1 entry 2642 bytes with total_stake at entry offset 32 + 2592 =
#      2624; ruleset 2 entry 2770 bytes with total_stake at 32 + 64 + 64 + 2592 = 2752 (u64 BE).
#  (2) ROUND 10: the exclusions are APPLIED, not assumed. For every member m and every reporting seat s the
#      verdict skips the seat when its owner equals m's owner (the registry row's payee_fp) or its key equals m's
#      fp (nodus_storage_member_verdict, nodus_witness_v2_storage.c:1373-1381), counts I = Σ power of the remaining
#      reporting seats and Y = Σ power of those with bit 1, and decides 2·I <= P_total -> NO_EVIDENCE, 3·Y > 2·I -> OK,
#      else NOT_OK (:1388-1393). load_seats reads each seat's key (SHA3-512 of the entry's pubkey, :1548-1551) and
#      owner (ruleset 2: the entry's owner_fp, :1403-1407, vset_wire.h:78-84) from snapshot(H); with equal power
#      (1) the power sums are seat counts and P_total = N. The stored self-bit is not assumed zero
#      (reporter.c:468 never sets it, but it is not relied on): an excluded seat's bit is skipped, whatever it is.
VSET_HDR=78                # shared/dnac/vset_wire.h:141 DNA_VSET_HDR_LEN
# snap_totals NODE H -> "active_count|ruleset|total_stake,total_stake,…" of snapshot(H), decoded from the blob
snap_totals() {
    local db meta n rs ent tot totals shash
    db=$(db_of "$1")
    meta=$(sqlite3 -separator '|' -cmd '.timeout 5000' "$db" \
        "SELECT active_count, hex(substr(snapshot_blob, 11, 4)), hex(snapshot_hash) FROM validator_set_snapshots WHERE epoch_start = $2;") \
        || die "snapshot($2) on node$1 could not be read"
    [ -n "$meta" ] || die "snapshot($2) is absent on node$1 — the settlement reads it (nodus_witness_v2_storage.c:1519)"
    # the snapshot HASH is part of the compared line: seat keys and owners (load_seats) are read from node 1 only, so
    # every live node must hold the same snapshot bytes
    n="${meta%%|*}"; rs=$(( 16#$(cut -d'|' -f2 <<< "$meta") )); shash=$(cut -d'|' -f3 <<< "$meta")
    case "$rs" in
        1) ent=2642; tot=2624 ;;     # vset_wire.h:142 DNA_VSET_ENTRY_LEN; 32 + 2592
        2) ent=2770; tot=2752 ;;     # vset_wire.h:143 DNA_VSET_ENTRY_LEN_V2; 32 + 64 + 64 + 2592
        *) die "snapshot($2) on node$1 carries selection_ruleset $rs — no layout is known for it" ;;
    esac
    totals=$(sqlite3 -cmd '.timeout 5000' "$db" \
        "WITH RECURSIVE i(k) AS (SELECT 0 UNION ALL SELECT k + 1 FROM i WHERE k + 1 < $n)
         SELECT hex(substr(snapshot_blob, $(( VSET_HDR + tot + 1 )) + k * $ent, 8))
           FROM validator_set_snapshots, i WHERE epoch_start = $2 ORDER BY k;") \
        || die "snapshot($2)'s entries on node$1 could not be read"
    echo "$n|$rs|$shash|$(printf '%s' "$totals" | tr '\n' ',')"
}
check_verdict_prereqs() {  # H — the epoch whose snapshot(H) the settlement of H reads
    local h="$1" r n first="" first_n="" s cnt rs tots t t0 first_tot
    for n in "${ALIVE[@]}"; do
        s=$(snap_totals "$n" "$h")
        if [ -z "$first" ]; then first="$s"; first_n="$n"
        elif [ "$s" != "$first" ]; then die "snapshot($h) differs between node$first_n ($first) and node$n ($s)"; fi
    done
    cnt="${first%%|*}"; rs="${first#*|}"; rs="${rs%%|*}"; tots="${first##*|}"
    [ "$cnt" = "$N" ] || die "snapshot($h) holds $cnt seat(s), expected $N"
    first_tot=""
    for t in ${tots//,/ }; do
        [[ "$t" =~ ^[0-9A-F]{16}$ ]] && [ "$t" != 0000000000000000 ] || die "snapshot($h): an entry's total_stake is '$t' (zero or unreadable)"
        if [ -z "$first_tot" ]; then first_tot="$t"
        elif [ "$t" != "$first_tot" ]; then die "snapshot($h) (ruleset $rs): seat powers are NOT equal (total_stake values $tots) — the seat-count bound is not the source verdict here"; fi
    done
    load_seats "$h"
}
# load_seats H — the seats of snapshot(H) as the SETTLEMENT reads them (round 10, row 2): per seat s, the seat KEY
# seat_fp = SHA3-512(pubkey) (nodus_witness_v2_storage.c:1548-1551, qgp_sha3_512 over the entry's pubkey) and the seat
# OWNER owner_fp. Ruleset 2 (every snapshot built at key generation >= 4, nodus_witness_vset.c:475-481, so every
# epoch this scenario reads) takes the owner from the ENTRY (nodus_storage_seat_owners, v2_storage.c:1403-1407);
# entry layout shared/dnac/vset_wire.h:78-84: voter_id 32, validator_id 64, owner_fp 64 (entry offset 96), consensus_pk
# 2592 (offset 160), after the 78-byte header. Ruleset 1 takes the owner from the validator row keyed by the migrated
# validator id (v2_storage.c:1414-1440, dna_validator_id_migrated), which this harness cannot derive: a ruleset-1
# snapshot is a named FAIL (that part is stopped, never guessed).
declare -A SEAT_FP SEAT_OWN
load_seats() {             # H
    local h="$1" meta n rs s off pk
    [ -z "${SEAT_FP["$h|0"]+x}" ] || return 0
    meta=$(sqlite3 -separator '|' -cmd '.timeout 5000' "$(db_of 1)" \
        "SELECT active_count, hex(substr(snapshot_blob, 11, 4)) FROM validator_set_snapshots WHERE epoch_start = $h;") \
        || die "snapshot($h) could not be read on node1"
    [ -n "$meta" ] || die "snapshot($h) is absent on node1"
    n="${meta%%|*}"; rs=$(( 16#${meta#*|} ))
    [ "$rs" = 2 ] || die "snapshot($h) carries selection_ruleset $rs: the seat owners of a ruleset-1 snapshot come from the validator row by migrated id (nodus_witness_v2_storage.c:1414-1440), which the harness cannot derive — the verdict's owner exclusion cannot be applied here"
    for (( s = 0; s < n; s++ )); do
        off=$(( VSET_HDR + s * 2770 ))                      # vset_wire.h:143 DNA_VSET_ENTRY_LEN_V2
        pk=$(sqlite3 -cmd '.timeout 5000' "$(db_of 1)" "SELECT hex(substr(snapshot_blob, $(( off + 160 + 1 )), 2592)) FROM validator_set_snapshots WHERE epoch_start = $h;")
        [ "${#pk}" = 5184 ] || die "snapshot($h) seat $s: the consensus pubkey is ${#pk} hex characters, expected 5184"
        SEAT_FP["$h|$s"]=$(printf '%s' "$pk" | xxd -r -p | openssl dgst -sha3-512 -binary | xxd -p -c 256 | tr -d '\n')
        SEAT_OWN["$h|$s"]=$(sqlite3 -cmd '.timeout 5000' "$(db_of 1)" "SELECT lower(hex(substr(snapshot_blob, $(( off + 96 + 1 )), 64))) FROM validator_set_snapshots WHERE epoch_start = $h;")
        [[ "${SEAT_FP["$h|$s"]}" =~ ^[0-9a-f]{128}$ ]] && [[ "${SEAT_OWN["$h|$s"]}" =~ ^[0-9a-f]{128}$ ]] || die "snapshot($h) seat $s: the key / owner could not be decoded"
    done
}
declare -A RB_Y RB_GRACE RB_HU RB_I RB_YE MOWN    # RB_I / RB_YE: I and Y of the SOURCE verdict (exclusions applied), MOWN: a member's owner (payee_fp)
RB_N=0; RB_MEMBERS=""; EP_H=0
# epoch_reads H — the members of set(H), their grace and held_union, and the committed reports of
# epoch H, from every live node (identical or FAIL); the live nodes are first waited (progress-
# bounded) to the report window's close.
epoch_reads() {            # H
    local h="$1" n out ref="" have_ref=0 body t idx i fp g hu seat hex byte
    local -a MEM=()
    wait_all $(( h + E + E / 2 ))
    check_verdict_prereqs "$h"
    for n in "${ALIVE[@]}"; do
        if ! out=$(sqlite3 -cmd '.timeout 5000' "$(db_of "$n")" \
            "BEGIN; SELECT 'tip|' || COALESCE(MAX(global_height), -1) FROM v2_blocks;
             SELECT 'mem|' || lower(hex(node_fp)) || '|' || grace_until || '|' || fail_streak FROM v2_storage_set_members WHERE epoch_start = $h ORDER BY node_fp;
             SELECT 'hu|' || lower(hex(node_fp)) || '|' || held_union || '|' || n_new FROM v2_storage_member_epoch WHERE epoch_start = $h ORDER BY node_fp;
             SELECT 'rep|' || seat || '|' || hex(bitmap) FROM v2_storage_reports WHERE epoch_start = $h ORDER BY seat;
             COMMIT;" 2>&1); then die "epoch $h read on node$n failed: $out"; fi
        t=$(sed -n 's/^tip|//p' <<< "$out" | sed -n '1p')
        [[ "$t" =~ ^[0-9]+$ ]] || die "epoch $h read on node$n: no tip ('$out')"
        [ "$t" -ge $(( h + E + E / 2 )) ] || die "internal: the reports of epoch $h were read at tip $t, before the report window closed ($(( h + E + E / 2 ))) — $MSG_LAYOUT"
        [ "$t" -lt $(( h + 2 * E )) ] || die "the reports of epoch $h were read at tip $t, at or past their settlement boundary $(( h + 2 * E )) where they are pruned — $MSG_LAYOUT"
        body=$(grep -v '^tip|' <<< "$out" || true)
        # initialisation is tracked apart from the body: an EMPTY first body is a body too and every
        # other node's body is compared with it (round-4 row 13)
        if [ "$have_ref" = 0 ]; then ref="$body"; have_ref=1
        elif [ "$body" != "$ref" ]; then
            diff <(printf '%s\n' "$ref") <(printf '%s\n' "$body") >&2 || true
            die "node$n's set / member_epoch / reports of epoch $h DIFFER from node${ALIVE[0]}'s (diff above)"
        fi
    done
    EP_H="$h"; RB_Y=(); RB_GRACE=(); RB_HU=(); RB_N=0; RB_I=(); RB_YE=()
    local so sf mo bit
    idx=0
    while IFS='|' read -r _ fp g _; do
        [ -n "$fp" ] || continue
        MEM[idx]="$fp"; RB_GRACE[$fp]="$g"; RB_Y[$fp]=0; RB_HU[$fp]=0; idx=$(( idx + 1 ))
    done < <(grep '^mem|' <<< "$ref" || true)
    while IFS='|' read -r _ fp hu _; do
        [ -n "$fp" ] || continue
        RB_HU[$fp]="$hu"
    done < <(grep '^hu|' <<< "$ref" || true)
    # the members' owners (the registry row's payee_fp — nodus_witness_v2_storage.c:1664 passes rows[].payee_fp)
    while IFS='|' read -r fp mo; do [ -z "$fp" ] || MOWN[$fp]="$mo"; done < <(sqlite3 -cmd '.timeout 5000' "$(db_of 1)" \
        "SELECT lower(hex(node_fp)) || '|' || lower(hex(payee_fp)) FROM v2_storage_nodes;")
    for (( i = 0; i < ${#MEM[@]}; i++ )); do RB_I[${MEM[$i]}]=0; RB_YE[${MEM[$i]}]=0; done
    while IFS='|' read -r _ seat hex; do
        [ -n "$seat" ] || continue
        RB_N=$(( RB_N + 1 ))
        [[ "$seat" =~ ^[0-9]+$ ]] && [ -n "${SEAT_FP["$h|$seat"]+x}" ] || die "epoch $h: a report names seat '$seat', which is not a seat of snapshot($h)"
        for (( i = 0; i < ${#MEM[@]}; i++ )); do
            byte="${hex:$(( 2 * (i / 8) )):2}"
            [ -n "$byte" ] || die "the bitmap of seat $seat in epoch $h is $(( ${#hex} / 2 )) byte(s), too short for member index $i"
            fp="${MEM[$i]}"
            bit=$(( (16#$byte >> (i % 8)) & 1 ))
            RB_Y[$fp]=$(( ${RB_Y[$fp]} + bit ))
            # the SOURCE's exclusion (nodus_storage_member_verdict, v2_storage.c:1373-1381): a seat whose owner equals the
            # member's owner or whose key equals the member's fp does not count, for or against
            sf="${SEAT_FP["$h|$seat"]}"; so="${SEAT_OWN["$h|$seat"]}"
            [ -n "${MOWN[$fp]+x}" ] || die "epoch $h: member ${fp:0:16}… has no registry row (no owner)"
            if [ "$so" = "${MOWN[$fp]}" ] || [ "$sf" = "$fp" ]; then continue; fi
            RB_I[$fp]=$(( ${RB_I[$fp]} + 1 )); RB_YE[$fp]=$(( ${RB_YE[$fp]} + bit ))
        done
    done < <(grep '^rep|' <<< "$ref" || true)
    RB_MEMBERS="${MEM[*]}"
    [ "${#MEM[@]}" -ge 1 ] || die "the frozen storage set of epoch $h has no member row"
    [ $(( 2 * RB_N )) -gt "$N" ] || die "only $RB_N of $N seats committed a report for epoch $h — F1 (more than half the power) cannot hold, nothing settles"
}
# epoch_verdict FP -> EV = grace | none | ok | dead | undetermined (for the epoch of the last epoch_reads)
in_set_or_die() {          # FP — the member must be in set(EP_H) of the last epoch_reads (round 7: a named FAIL, not an unbound variable)
    local who
    who=$(fp_node "$1"); if [ -n "$who" ]; then who="node$who"; else who="the candidate"; fi
    [ -n "${RB_GRACE[$1]+x}" ] || die "epoch $EP_H: ${1:0:16}… ($who) is listed for a check but is not in the frozen storage set of epoch $EP_H (members: ${RB_MEMBERS})"
}
epoch_verdict() {
    in_set_or_die "$1"
    local fp="$1" i="${RB_I[$1]}" ye="${RB_YE[$1]}"
    if [ "${RB_GRACE[$fp]}" -gt "$EP_H" ]; then EV=grace; return 0; fi     # in grace: not probed, weight 0
    if [ "${RB_HU[$fp]}" = 0 ]; then EV=none; return 0; fi                # no assignment in either epoch: not probed
    # the SOURCE verdict (round 10): I / Y with the seat exclusions applied (epoch_reads), P_total = N seats of equal
    # power; 2·I <= P_total is NO_EVIDENCE (the fail_streak would not move: not a case this scenario asserts, a FAIL),
    # 3·Y > 2·I is OK, else NOT OK
    if [ $(( 2 * i )) -le "$N" ]; then EV=undetermined
    elif [ $(( 3 * ye )) -gt $(( 2 * i )) ]; then EV=ok
    else EV=dead; fi
}
fp_node() {                # FP -> the node index whose identity it is, '' if none (the candidate)
    local k
    for k in $(seq 1 "$N"); do if [ "${FP[$k]}" = "$1" ]; then echo "$k"; return 0; fi; done
}
# count_log_lines FIXED_STRING NODE… — the number of lines holding the string across those nodes' logs; an
# unreadable log (grep rc other than 0 / 1) is a FAIL, never a count of 0 (round-4 row 19's rule, here too)
count_log_lines() {
    local pat="$1" n c total=0 grc
    shift
    for n in "$@"; do
        [ -r "$(node_log "$n")" ] || die "node$n's log $(node_log "$n") is not readable"
        grc=0; c=$(grep -cF -- "$pat" "$(node_log "$n")") || grc=$?
        { [ "$grc" = 0 ] || [ "$grc" = 1 ]; } || die "grep of node$n's log failed (rc $grc)"
        total=$(( total + c ))
    done
    echo "$total"
}
pool1_of() { sqlite3 -cmd '.timeout 5000' "$(db_of 1)" "SELECT balance FROM v2_treasury WHERE pool_id = 1;"; }
acc_of()   { sqlite3 -cmd '.timeout 5000' "$(db_of 1)" "SELECT COALESCE(SUM(amount), 0) FROM v2_reward_accrual WHERE lower(hex(owner_fp)) = '$1';"; }

# epoch_service_read H — the bits and the settlement INPUTS of epoch H, read in the report window:
#  * every member of set(H) that is eligible (not in grace, held_union > 0) must be: OK for a member
#    that runs a node (it answered its probes), dead for the candidate (no seat sets its bit); a
#    member in grace / without assignment must carry no bit (it was not probed);
#  * the new holders registered for this epoch (NEWH_AT) must be eligible in it, with the bit above;
#    the dropped holders registered for it (ZERO_AT) must carry no bit and held_union 0;
#  * the expected settlement at B = H + 2E from the source formula (nodus_witness_v2_storage.c
#    st_settle, :1481-1521 weights, :1651-1690 pay): weight(m) = P x held_union(m, H) unless m is in
#    grace at H; W = Σ weights (the NOT OK member's weight counts); budget = pool1 >> 16
#    (NODUS_V2_GEN_REWARD_DIVISOR_LOG2); an OK member is paid floor(budget x weight / W) to its owner
#    (st_muldiv), a NOT OK member nothing, and pool 1 falls by exactly the sum paid. P cancels, so
#    floor(budget x held_union / Σ held_union). Pool 1 and the owners' accrual change only at
#    boundaries, so the pre values read here (after boundary H + E, before H + 2E) are the values
#    the settlement at H + 2E starts from.
#  * the candidate's NOT OK is tied to the reporter's own line "storage member <fp16>.. was never
#    reachable on 0x72 in epoch H=<H> — NOT OK" (nodus_witness_storage_reporter.c:579-580, expire() at the
#    epoch's close), counted over the live nodes' logs: one per reporting seat at least. A target that
#    was never PROBED (NOPROBE: itself, no eligible segment) logs no such line, so the line separates
#    "probed and unreachable" from "not probed" (round-4 row 4, the assertable half).
declare -A EPV EPM EPH DER_HU    # per epoch H: the verdict "h|fp", the member list, held_union "h|fp", the independently derived "b|fp" -> "hu|nn"
epoch_service_read() {     # H
    local h="$1" fp k kind sumw=0 hu pool budget share anypos=0 nlines
    epoch_reads "$h"
    EPM[$h]="$RB_MEMBERS"
    for fp in $RB_MEMBERS; do
        epoch_verdict "$fp"
        EPV["$h|$fp"]="$EV"; EPH["$h|$fp"]="${RB_HU[$fp]}"
        k=$(fp_node "$fp")
        # held_union as the settlement will use it must equal the value derived INDEPENDENTLY from the
        # assignment relation at the boundary cell of this epoch (round-4 row 8) where one was derived
        if [ -n "${DER_HU["$h|$fp"]+x}" ]; then
            [ "${DER_HU["$h|$fp"]%%|*}" = "${RB_HU[$fp]}" ] || die "epoch $h: ${fp:0:16}… has held_union ${RB_HU[$fp]} in v2_storage_member_epoch, the assignment relation derives ${DER_HU["$h|$fp"]%%|*}"
        fi
        if [ "$EV" = grace ] || [ "$EV" = none ]; then
            [ "${RB_Y[$fp]}" = 0 ] || die "epoch $h: ${fp:0:16}… is $EV (in grace / no assignment) but ${RB_Y[$fp]} seat(s) carry its bit"
        elif [ "$fp" = "$DEAD_FP" ]; then
            [ "$EV" = dead ] || die "epoch $h: the candidate (no node) is eligible but its verdict is '$EV' (${RB_Y[$fp]} of $RB_N seats carry its bit; I ${RB_I[$fp]}, Y ${RB_YE[$fp]}) — expected NOT OK with bit 0 in every seat"
            [ "${RB_Y[$fp]}" = 0 ] || die "epoch $h: the candidate (no node) is NOT OK but ${RB_Y[$fp]} seat(s) carry its bit — a node that runs nothing cannot be OK in a probe"
            nlines=$(count_log_lines "storage member ${fp:0:16}.. was never reachable on 0x72 in epoch H=$h — NOT OK" "${ALIVE[@]}")
            [ "$nlines" -ge "$RB_N" ] || die "epoch $h: the candidate has bit 0 in all $RB_N reports but the live nodes' logs hold only $nlines 'never reachable on 0x72 in epoch H=$h — NOT OK' line(s): it was not probed-and-unreachable (a not-probed target has bit 0 too)"
            echo "[ok] epoch $h: the candidate ${fp:0:16}… — $nlines reporter line(s) 'never reachable on 0x72 in epoch H=$h — NOT OK' (>= the $RB_N reports): probed and unreachable, not merely unprobed"
        else
            [ "$EV" = ok ] || die "epoch $h: node$k (${fp:0:16}…) is eligible and answers its probes but its verdict is '$EV' (${RB_Y[$fp]} of $RB_N seats carry its bit)"
        fi
    done
    for fp in ${NEWH_AT[$h]:-}; do
        epoch_verdict "$fp"
        { [ "$EV" = ok ] || [ "$EV" = dead ]; } || die "epoch $h: the new holder ${fp:0:16}… is not eligible in its first eligible epoch (verdict '$EV')"
        echo "[ok] epoch $h: the new holder ${fp:0:16}… $([ "$EV" = ok ] && echo "has its bit in ${RB_Y[$fp]} of $RB_N reports (it answers its probes)" || echo "has bit 0 in all $RB_N reports (it runs no node)")"
        if [ "$EV" = ok ] && [ "$fp" = "${FP[$JOINER]}" ] && [ -n "${J_BASE:-}" ]; then
            # round-4 row 6: where file serving is claimed, the probe is answered FROM THE FILE — the reporter
            # answers from the block store first and from seg-<k>.ok only when the store lacks the sample
            # (nodus_witness_storage_reporter.c:280-286); this node's store starts above segment 1's last height
            echo "[ok] epoch $h: node$JOINER's probes of segment 1 can only be answered from its segment FILE (its block store starts at $J_BASE, above the segment's last height $P)"
        fi
    done
    for fp in ${ZERO_AT[$h]:-}; do
        in_set_or_die "$fp"
        { [ "${RB_Y[$fp]}" = 0 ] && [ "${RB_HU[$fp]}" = 0 ]; } || die "epoch $h: the dropped holder ${fp:0:16}… still has held_union ${RB_HU[$fp]} / ${RB_Y[$fp]} bit(s) after the overlap epoch"
        echo "[ok] epoch $h: the dropped holder ${fp:0:16}… is no longer probed (held_union 0, bit 0 in every report)"
    done
    # the settlement inputs
    pool=$(pool1_of); [[ "$pool" =~ ^[0-9]+$ ]] || die "epoch $h: pool 1 unreadable ('$pool')"
    budget=$(( pool >> DIV_LOG2 ))
    for fp in $RB_MEMBERS; do
        epoch_verdict "$fp"
        if [ "$EV" != grace ] && [ "$EV" != none ]; then sumw=$(( sumw + ${RB_HU[$fp]} )); fi
    done
    SETTLE_POOL[$h]="$pool"
    for fp in $RB_MEMBERS; do
        epoch_verdict "$fp"
        share=0
        if [ "$EV" = ok ] && [ "$sumw" -gt 0 ]; then share=$(( budget * ${RB_HU[$fp]} / sumw )); fi
        if [ "$share" -gt 0 ]; then anypos=1; fi
        SETTLE_EXP["$h|$fp"]="$share"
        SETTLE_ACC["$h|$fp"]=$(acc_of "$fp")
    done
    # an all-zero settlement must not pass (round-4 row 7): pool 1 is read from the chain just above, and
    # in every paying epoch (a payday boundary empties the accrual and is not asserted) at least one paid member
    # must have a POSITIVE expected share
    if ! is_payday $(( h + 2 * E )); then
        [ "$budget" -gt 0 ] || die "epoch $h: the budget (pool 1 $pool >> $DIV_LOG2) is 0 — pool 1 is not funded on the chain; every share would be 0"
        [ "$anypos" = 1 ] || die "epoch $h: no member has a positive expected share (Σ weight $sumw, budget $budget) — an all-zero settlement does not pass"
    fi
    SETTLE_ACC["$h|members"]="$RB_MEMBERS"
    echo "[ok] epoch $h: bits and verdicts as expected (N=$RB_N reports); pool 1 $pool, budget $budget, Σ weight units $sumw — settlement due at $(( h + 2 * E ))"
    PEND_READ=$(printf '%s\n' $PEND_READ | awk -v h="$h" '$0 != h' | tr '\n' ' ')
    PEND_POST="$PEND_POST $h"
}
# epoch_service_post H — at B = H + 2E: each member's owner's accrual rose by exactly the expected share
# and pool 1 fell by exactly their sum (a payday boundary empties the accrual: skipped, said so)
epoch_service_post() {     # H
    local h="$1" b fp d sum=0 pool who
    b=$(( h + 2 * E ))
    wait_all "$b"
    if is_payday "$b"; then
        echo "[info] epoch $h: the settlement boundary $b is a payday (it empties the accrual) — the amounts are NOT asserted for this epoch"
    else
        for fp in ${SETTLE_ACC["$h|members"]}; do
            d=$(( $(acc_of "$fp") - ${SETTLE_ACC["$h|$fp"]} ))
            who=$(fp_node "$fp"); if [ -n "$who" ]; then who="node$who"; else who="the candidate"; fi
            [ "$d" = "${SETTLE_EXP["$h|$fp"]}" ] || die "settlement of epoch $h at $b: the owner ${fp:0:16}… ($who) was paid $d, the source formula says ${SETTLE_EXP["$h|$fp"]}"
            sum=$(( sum + d ))
        done
        pool=$(pool1_of)
        [ $(( ${SETTLE_POOL[$h]} - pool )) = "$sum" ] || die "settlement of epoch $h at $b: pool 1 fell by $(( ${SETTLE_POOL[$h]} - pool )), the shares paid sum to $sum"
        echo "[ok] settlement of epoch $h at $b: every member's owner was paid its exact share ($(for fp in ${SETTLE_ACC["$h|members"]}; do printf '%s ' "${SETTLE_EXP["$h|$fp"]}"; done)), pool 1 fell by $sum"
    fi
    PEND_POST=$(printf '%s\n' $PEND_POST | awk -v h="$h" '$0 != h' | tr '\n' ' ')
}
service_reads() {          # [TIP] — serve what is open at TIP (default: the tip read now)
    local h t wt
    t="${1:-$(tip_of 1)}"
    for h in $PEND_READ; do
        wt=$(( h + E + E / 2 ))
        if [ "$t" -ge $(( h + 2 * E )) ]; then die "the report window of epoch $h (tip $wt .. $(( h + 2 * E - 1 ))) closed before it could be read: the chain is at $t (it made blocks on its own while a step waited, and the reports are pruned at $(( h + 2 * E ))) — $MSG_LAYOUT"; fi
        if [ "$t" -ge "$wt" ]; then epoch_service_read "$h"; fi
    done
}
service_posts() {          # [TIP]
    local h t
    t="${1:-$(tip_of 1)}"
    for h in $PEND_POST; do
        if [ "$t" -ge $(( h + 3 * E )) ]; then die "internal: the settlement of epoch $h (boundary $(( h + 2 * E ))) was passed without its check (tip $t) — $MSG_LAYOUT"; fi
        if [ "$t" -ge $(( h + 2 * E )) ]; then epoch_service_post "$h"; fi
    done
}
# advance_to T — pump to T, serving every queued report window and settlement check on the way. ROUND 8: the queues
# are served BEFORE the first pump too. The chain makes blocks on its own (create_empty_blocks every 60 s,
# stagef_env.sh:1018-1056) while the script waits (a registration, a restart, a cell read), so a window can already be
# OPEN when a pump starts; the old loop only stopped at windows still AHEAD and read after pumping, which passed run
# 9's window of epoch 525 (tip 547 .. 554) from tip 547 to 555. A window that closed before it could be read (the
# tip is at or past h + 2E) still FAILs by name in service_reads; nothing is retried. It also stops at the first
# settlement boundary h + 2E of a queued read, so its check is served at that boundary and not after the next one.
#
# ROUND 10 (row 8): on EVERY pass the tip is read ONCE and both what is served and the pump target come from that same
# tip. A window that opens after that read has its opening height above it, so it is a stop (`wt > t`) and the pump
# cannot run past it (a stop at or below the real tip makes the pump a no-op and the next pass serves it); a window
# at or below it was served before the target was chosen. The old loop served at one tip and chose the target from a
# later one, so a window opening between the two was neither served nor a stop.
advance_to() {
    local T="$1" nxt h wt t
    while :; do
        t=$(tip_of 1)
        service_reads "$t"
        service_posts "$t"
        nxt="$T"
        for h in $PEND_READ; do
            wt=$(( h + E + E / 2 ))
            if [ "$wt" -gt "$t" ] && [ "$wt" -lt "$nxt" ]; then nxt="$wt"; fi
        done
        for h in $PEND_POST; do
            wt=$(( h + 2 * E ))
            if [ "$wt" -gt "$t" ] && [ "$wt" -lt "$nxt" ]; then nxt="$wt"; fi
        done
        pump_raw "$nxt"
        if [ "$(tip_of 1)" -ge "$T" ]; then service_reads; service_posts; return 0; fi
    done
}
# pump_to TARGET — the pump every step uses: with queued checks it goes through advance_to (served first, stops at
# every window and settlement boundary); with none, or from inside advance_to's own serving, the bare pump. The
# serving code never pumps (epoch_reads / epoch_service_post only wait), so there is no recursion.
PUMP_IN=0
pump_to() {
    if [ "$PUMP_IN" = 1 ] || { [ -z "${PEND_READ// /}" ] && [ -z "${PEND_POST// /}" ]; }; then
        pump_raw "$1"
        return 0
    fi
    PUMP_IN=1
    advance_to "$1"
    PUMP_IN=0
}

# drain_pending — advance through EVERY queued epoch's report window and settlement boundary, then FAIL if
# any queued read or settlement check is still pending (round-4 rows 18, 21). A read adds its settlement to the
# queue, so the loop runs until both queues are empty; it never reads a window that has no queued boundary.
drain_pending() {
    local target h guard=0
    while [ -n "${PEND_READ// /}" ] || [ -n "${PEND_POST// /}" ]; do
        target=0
        for h in $PEND_READ; do [ $(( h + E + E / 2 )) -le "$target" ] || target=$(( h + E + E / 2 )); done
        for h in $PEND_POST; do [ $(( h + 2 * E )) -le "$target" ] || target=$(( h + 2 * E )); done
        guard=$(( guard + 1 ))
        [ "$guard" -le 8 ] || die "drain_pending: the queues did not empty after 8 passes (reads '${PEND_READ# }', settlements '${PEND_POST# }')"
        advance_to "$target"
    done
    [ -z "${PEND_READ// /}" ] && [ -z "${PEND_POST// /}" ] || die "internal: queued checks are still pending (reads '${PEND_READ# }', settlements '${PEND_POST# }')"
}

# the next boundary: its cell, then (once the candidate is registered) its fail_streak transition
D_TRACK=0; D_PHASE=pre; D_PREV=0; DEP=0; REV=0; CUR_B=0
next_boundary() {          # LABEL R
    CUR_B=$(( CUR_B + E ))
    boundary_cell "$1" "$CUR_B" "$2"
    if [ "$D_TRACK" = 1 ]; then track_d; fi
}
# the candidate's PHASE at every boundary: it leaves the basis exactly at fail_streak 3, and the ONLY way back is
# 14 -> 0 (14 + 1 is written as 0). The counter VALUE itself (+0 or +1 is NOT accepted any more) is asserted
# EXACTLY at every boundary by check_transition_exact from the settled epoch H = B - 2E (round-4 row 3).
track_d() {
    local fs
    fs=$(reg_fs "$D_FP")
    [[ "$fs" =~ ^[0-9]+$ ]] || die "boundary $CUR_B: the candidate's fail_streak is '$fs'"
    case "$D_PHASE" in
        pre)
            if in_basis "$D_FP"; then
                [ "$fs" -lt 3 ] || die "boundary $CUR_B: fail_streak $fs >= 3 but the candidate is still in the basis"
            else
                [ "$fs" = 3 ] || die "boundary $CUR_B: the candidate left the basis with fail_streak $fs, expected exactly 3"
                D_PHASE=out; DEP="$CUR_B"
            fi
            D_PREV="$fs" ;;
        out)
            if in_basis "$D_FP"; then
                { [ "$D_PREV" = 14 ] && [ "$fs" = 0 ]; } || die "boundary $CUR_B: the candidate returned to the basis with fail_streak $fs after $D_PREV — the return is 14 -> 0 only (never early, never from another value)"
                D_PHASE=back; REV="$CUR_B"
            else
                [ "$fs" -ge 3 ] || die "boundary $CUR_B: fail_streak $fs below 3 while the candidate is out of the basis"
            fi
            D_PREV="$fs" ;;
        *) : ;;
    esac
}
# note_new_holders B — every member with n_new > 0 at boundary B: its first eligible epoch is its grace end;
# epoch_service_read asserts, in that epoch's reports, the member's bit (it answers its probes) or 0 (the candidate)
note_new_holders() {       # B
    local fp g nn
    while IFS='|' read -r _ fp _ nn; do
        if [ "$nn" -le 0 ]; then continue; fi
        g=$(reg_grace "$fp")
        [ "$g" -ge $(( $1 + E )) ] || die "boundary $1: ${fp:0:16}… has n_new $nn but grace_until $g (K9 raises it to at least B + E)"
        NEWH_AT[$g]="${NEWH_AT[$g]:-} $fp"
    done < <(cell_lines mepoch | awk -F'|' -v b="$1" '$1 == b')
}
# vote_copies V — STORAGE_COPIES = V voted two tips after the boundary just read, effective at the SECOND
# boundary on (param 25's wait is one epoch, ERGONOMIC = E at the short build, plus the layout margin)
vote_copies() {            # V
    advance_to $(( CUR_B + 2 ))
    cc_guard 1
    E25=$(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN ))
    VOTE_B=$(( (E25 + E - 1) / E * E ))
    # Round 9: the change lands at CUR_B + 2E when the proposal's tip is at most CUR_B + 9 (E25 = tip + 1 + ERGONOMIC grace
    # + margin = tip + 21 <= CUR_B + 30), and at CUR_B + 3E when the chain made blocks on its own (or the pump landed) beyond
    # that before the vote; the guard keeps the tip <= CUR_B + E - 4, so no other boundary is possible. The old single
    # accepted value CUR_B + 2E was a 7-block tip window; both are accepted now and copies_boundaries reads one cell per
    # boundary with the OLD R until the change lands.
    { [ "$VOTE_B" = $(( CUR_B + 2 * E )) ] || [ "$VOTE_B" = $(( CUR_B + 3 * E )) ]; } || die "the param-25 effective height $E25 puts the change at boundary $VOTE_B, expected $(( CUR_B + 2 * E )) or $(( CUR_B + 3 * E )) — $MSG_LAYOUT"
    echo "[ok] tip $CCG_TIP — node1 proposes STORAGE_COPIES=$1 effective E25=$E25 (the change lands at the boundary $VOTE_B)"
    propose STORAGE_COPIES "$1" "$E25" "$LOGD/propose_copies_${1}_$CUR_B.log"
    wait_cc_row "$PARAM_COPIES" "$E25" "$1" 20
    [ "$CC_CB" -lt "$E25" ] || die "the STORAGE_COPIES row committed at $CC_CB, not before its effective height $E25"
}

# copies_boundaries OLD_R NEW_R LABEL — the cells after vote_copies: one with OLD_R per boundary before the change
# (zero, one or... as VOTE_B says), then the boundary where the change lands, read with NEW_R
copies_boundaries() {
    while [ $(( CUR_B + E )) -lt "$VOTE_B" ]; do next_boundary "$3-pre" "$1"; done
    next_boundary "$3" "$2"
}

# ── hf9: storage CLI (test_storage_archive.sh's) ────────────────────
consent_make() {           # NODE OWNER OUT LOG
    local n="$1" own="$2" out="$3" log="$4" crc=0 exp
    exp=$(( $(tip_of "$n") + CONSENT_AHEAD ))
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port "$n")" -i "$(node_keys "$n")" \
        storage consent --owner "$own" --expiry "$exp" --out "$out" > "$log" 2>&1 || crc=$?
    cat "$log"
    [ "$crc" = 0 ] && [ -s "$out" ] || die "node$n's storage consent (owner ${own:0:16}...) was refused (rc $crc, see $log)"
}
register_member() {       # NODE — consent to itself as owner, register, wait for the ACTIVE row
    local n="$1" keys cf log port h wrc fp
    keys=$(node_keys "$n"); fp="${FP[$n]}"
    cf="$LOGD/consent_node$n.txt"; log="$LOGD/register_node$n.log"
    consent_make "$n" "$fp" "$cf" "$LOGD/consent_node$n.log"
    port=$(stagef_tcp_port "$(dial_for "$n" "$keys")")
    "$CLI" -s 127.0.0.1 -p "$port" storage register --keys "$keys" --consent "$cf" \
        --submit "127.0.0.1:$port" > "$log" 2>&1 || { cat "$log" >&2; die "storage register for node$n failed (see $log)"; }
    cat "$log"
    grep -q '^accepted: mempool CheckTx approved' "$log" || die "storage register for node$n: no CheckTx approval line (see $log)"
    h=$(stagef_cmt_wait_row "$(db_of "$n")" \
        "SELECT COUNT(*) FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '$fp' AND status = 1;") && wrc=0 || wrc=$?
    case "$wrc" in
        0) ;;
        1) die "chain STALLED waiting for node$n's registry row (tip $h)" ;;
        *) die "node$n's registration did not land within 20 heights (tip $h) — dropped, not delayed" ;;
    esac
    echo "[ok] node$n registered as a storage node (row visible at tip $h)"
}

# ── 0/1. preconditions: a fresh cluster on this build ───────────────
for n in $(seq 1 "$N"); do
    node_runs_srv "$n" || die "node$n is not running STAGEF_NODUS_BIN ($(readlink -f "$SRV")) — bring the cluster up with it"
done
for n in $(seq 1 "$N"); do
    bl=$(grep -o 'HF-6 rule-set generation 4 vote D4 0x[0-9a-f]* (param 18 RULESET_GEN_ROLES, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-6 rule-set generation 4 vote D4 0x$D4_HEX (param 18 RULESET_GEN_ROLES, switch spec v1)" ] || die \
        "node$n's startup banner D4 line is '${bl:-none}', not the CLI's D4 0x$D4_HEX (param 18, switch spec v1)"
    bl=$(grep -o 'HF-7 rule-set generation 5 vote D5 0x[0-9a-f]* (param 22 RULESET_GEN_ROOTS, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-7 rule-set generation 5 vote D5 0x$D5_HEX (param 22 RULESET_GEN_ROOTS, switch spec v1)" ] || die \
        "node$n's startup banner D5 line is '${bl:-none}', not the CLI's D5 0x$D5_HEX (param 22, switch spec v1)"
    bl=$(grep -o 'HF-9 rule-set generation 6 vote D6 0x[0-9a-f]* (param 24 RULESET_GEN_TRIE, switch spec v[0-9]*)' \
            "$(node_log "$n")" | tail -1 || true)
    [ "$bl" = "HF-9 rule-set generation 6 vote D6 0x$D6_HEX (param 24 RULESET_GEN_TRIE, switch spec v1)" ] || die \
        "node$n's startup banner D6 line is '${bl:-none}', not the CLI's D6 0x$D6_HEX (param 24, switch spec v1)"
done
for p in "$PARAM_HF2" "$PARAM_HF3" "$PARAM_GEN2" "$PARAM_EVM" "$PARAM_RET16" "$PARAM_HF6" "$PARAM_HF7" "$PARAM_TRIE" "$PARAM_COPIES"; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM chain_config_history WHERE param_id = $p;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1 already holds a param-$p row — this scenario needs a fresh bring-up"
done
for tb in v2_validator_roles delegations v2_storage_nodes tokens v2_names; do
    [ "$(sqlite3 "$ref_db0" "SELECT COUNT(*) FROM $tb;" 2>/dev/null || echo ERR)" = 0 ] \
        || die "node1's $tb is not empty — this scenario needs a fresh bring-up"
done
INIT_H=$(sed -n 's/^initial_height *= *\([0-9][0-9]*\) *$/\1/p' "$CONF")
[ -n "$INIT_H" ] || die "no initial_height in $CONF"
[ "$INIT_H" = 0 ] && INIT_H=1
PIN_FILE="$BASE_DIR/v2_genesis_pin"
[ -s "$PIN_FILE" ] || die "no $PIN_FILE — needed by the fresh-replay step (stagef_up_v2.sh writes it)"
PIN=$(cat "$PIN_FILE")
[ "${#PIN}" = 64 ] || die "the recorded pin is not 64 hex characters"
if [ "$WITH_STORAGE" = 1 ]; then
    D_FP=$(fp_of "$CAND")
    [ "${#D_FP}" = 128 ] || die "$CAND/nodus.fp is not 128 hex characters"
    grep -q "^dest_binding = ${D_FP}\$" "$CONF" || die "the genesis config binds no leaf to the candidate $CAND — export STAGEF_V2_CANDIDATES=1 before the bring-up"
    for k in $(seq 1 "$N"); do
        [ "$D_FP" != "${FP[$k]}" ] || die "the candidate is node$k's own identity"
    done
fi
stagef_cmt_pump_ready "$(db_of 1)" || die "the CLI-SPEND pump is not usable on this bring-up (reason above)"
[ "$VICTIM" != "$STAGEF_PUMP_SUBMIT_NODE" ] || die "the restart victim (node $VICTIM) is the pump's submit node — change STAGEF_PUMP_SUBMIT_NODE"
stagef_sentinel SETUP_OK
floor_diff "pre-hf9"
echo "[info] mode: $([ "$WITH_STORAGE" = 1 ] && echo "SHORT EPOCH (E=$E), storage included" || echo "PRODUCTION-CONSTANT edge run (E=$E), WITHOUT storage segments — the four storage members register at generation 5 (leg 5 populated); segment 1, B1, join, exit and param 25 are not run (header)")"

# ── 1. leaves, a token and a name — the populated legs (hf9) ────────
# (round-4 row 20: the production-constant run registers the four storage members too, so leg 5 is populated
# there; its leg 6 stays empty — no segment is reachable at E 720)
CLAIM_NODES="1 2 $MEMBERS_PRE"
for k in $CLAIM_NODES; do claim_leaf "$(node_keys "$k")" "$k"; done
# the token: node 1 creates it (test_cmt_token_create.sh's call), dialled through node 2
tport=$(stagef_tcp_port "$(dial_for 1 "$(node_keys 1)")")
tlog="$LOGD/token_create.log"
"$CLI" -s 127.0.0.1 -p "$tport" v2-envelope token-create --keys "$(node_keys 1)" \
    --name "$TK_NAME" --symbol "$TK_SYM" --decimals "$TK_DEC" --supply "$TK_SUPPLY" \
    --submit "127.0.0.1:$tport" > "$tlog" 2>&1 || { cat "$tlog" >&2; die "token-create from node1 was refused (see $tlog)"; }
tid=$(awk '/^  token_id=/{sub(/^  token_id=/,""); print}' "$tlog")
[ "${#tid}" = 128 ] || { cat "$tlog" >&2; die "token-create printed no 64-byte token_id"; }
th=$(stagef_cmt_wait_row "$(db_of 1)" "SELECT COUNT(*) FROM tokens WHERE lower(hex(token_id)) = '$tid';") && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "the tokens row did not appear (wait rc=$wrc, tip $th)"
echo "[ok] token ${tid:0:16}… created by node1 (tip $th)"
# (the name is registered right after the generation-2 edge, step 2: names open only from there)

# ── 2. the six votes to generation 5 (test_cmt_hf8_gen5.sh) ─────────
cc_guard 1
H2=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes HF2_ACTIVE=1 effective H2=$H2"
propose HF2_ACTIVE 1 "$H2" "$LOGD/propose_hf2.log"
wait_cc_row "$PARAM_HF2" "$H2" 1 20
[ "$CC_CB" -lt "$H2" ] || die "the HF2 row committed at $CC_CB, not before its effective height $H2"
pump_to $(( H2 + 1 ))
wait_all $(( H2 + 1 ))

cc_guard 1
H3=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes HF3_ACTIVE=1 effective H3=$H3"
propose HF3_ACTIVE 1 "$H3" "$LOGD/propose_hf3.log"
wait_cc_row "$PARAM_HF3" "$H3" 1 20
[ "$CC_CB" -lt "$H3" ] || die "the HF3 row committed at $CC_CB, not before its effective height $H3"
pump_to $(( H3 + 1 ))
wait_all $(( H3 + 1 ))

require_gen 1 1 0
D2_HEX="$RI_D2"
[ "${#D2_HEX}" = 16 ] && [ "$D2_HEX" = "$RI_CLI_D2" ] || die "the node's D2 '$D2_HEX' and the CLI's '$RI_CLI_D2' are not one 16-hex literal"
D2_DEC=$(( 16#$D2_HEX ))
cc_guard 1
H4=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN2=$D2_DEC effective H4=$H4"
propose RULESET_GEN2 "$D2_DEC" "$H4" "$LOGD/propose_gen2.log"
wait_cc_row "$PARAM_GEN2" "$H4" "$D2_DEC" 20
[ "$CC_CB" -lt "$H4" ] || die "the RULESET_GEN2 row committed at $CC_CB, not before its effective height $H4"
cross_edge gen2 "$H4"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_2" "$H4"; done
echo "[ok] rule-set generation 2 on 7/7 from H4=$H4"
# the name: node 2 registers it (test_cmt_hf8_gen5.sh's call). The CLI refuses below rule-set
# generation 2 — nodus-cli.c:8539-8544 (`name register`): "the node still runs rule-set generation N
# — names open at its RULESET_GEN2 height; nothing was built" (core_rt->generation < NODUS_RT_GEN_2)
# — so this is the first point the chain can take it; the row still exists long before the param-24 vote.
nlog="$LOGD/register_${NAME_B}.log"; port1=$(stagef_tcp_port 1)
"$CLI" -s 127.0.0.1 -p "$port1" name register "$NAME_B" --keys "$(node_keys 2)" \
    --submit "127.0.0.1:$port1" > "$nlog" 2>&1 || { cat "$nlog" >&2; die "name register $NAME_B from node2 failed (see $nlog)"; }
hn=$(stagef_cmt_wait_row "$(db_of 1)" \
    "SELECT COUNT(*) FROM v2_names WHERE name = CAST('$NAME_B' AS BLOB) AND lower(hex(owner)) = '${FP[2]}';") && wrc=0 || wrc=$?
[ "$wrc" = 0 ] || die "the v2_names row '$NAME_B' -> node2 did not land (wait rc=$wrc, tip $hn)"
echo "[ok] '$NAME_B' registered to node2 (tip $hn)"

cc_guard 1
HE=$(( CCG_TIP + 1 + GRACE_SAF + GRACE_MARGIN ))                 # param 14: SAFETY grace
H_WIN=$(( INIT_H + 256 + WINDOW_MARGIN ))                        # EVM rule (g)
[ "$HE" -ge "$H_WIN" ] || HE="$H_WIN"
HE=$(clear_of_boundary "$HE")
echo "[ok] tip $CCG_TIP — node1 proposes EVM_ACTIVE=$D_DEC effective HE=$HE (window floor $H_WIN)"
propose EVM_ACTIVE "$D_DEC" "$HE" "$LOGD/propose_evm.log"
wait_cc_row "$PARAM_EVM" "$HE" "$D_DEC" 20
[ "$CC_CB" -lt "$HE" ] || die "the EVM_ACTIVE row committed at $CC_CB, not before its effective height $HE"
cross_edge evm "$HE"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_EVM" "$H4"; done
echo "[ok] the EVM generation $GEN_EVM on 7/7 from HE=$HE"

cc_guard 1
H6=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_ROLES=$D4_DEC effective H6=$H6"
propose RULESET_GEN_ROLES "$D4_DEC" "$H6" "$LOGD/propose_hf6.log"
wait_cc_row "$PARAM_HF6" "$H6" "$D4_DEC" 20
[ "$CC_CB" -lt "$H6" ] || die "the RULESET_GEN_ROLES row committed at $CC_CB, not before its effective height $H6"
cross_edge hf6 "$H6"
HF6_LINE="HF-6: rule-set generation $GEN_EVM -> $GEN_4 and the validator migration at the end of height $(( H6 - 1 )) (param $PARAM_HF6 RULESET_GEN_ROLES, D4 0x$D4_HEX); height $H6 is judged under generation $GEN_4"
for n in $(seq 1 "$N"); do
    grep -qF "$HF6_LINE" "$(node_log "$n")" || die "node$n logged no '$HF6_LINE' line"
    require_gen "$n" "$GEN_4" "$H4"
done
echo "[ok] generation $GEN_4 on 7/7 from H6=$H6 (HF-6)"
vown=$(sqlite3 -separator '|' "$(db_of 1)" \
    "SELECT COUNT(*), COUNT(DISTINCT owner_fp), COALESCE(MIN(lower(hex(owner_fp))), '-') FROM v2_validator_roles;" 2>/dev/null || echo ERR)
[ "$vown" = "$N|1|$OWNER" ] || die \
    "the validator owners after the generation-4 edge are '$vown', expected '$N|1|${OWNER:0:16}...' — the build's DNAC_HF6_FOUNDATION_OWNER is not $([ -n "$OWN_KEYS" ] && echo 'STAGEF_HF6_OWNER_FP_HEX' || echo 'the K8 default')"

cc_guard 1
A5=$(clear_of_boundary $(( CCG_TIP + 1 + GRACE_ERG + GRACE_MARGIN )))
echo "[ok] tip $CCG_TIP — node1 proposes RULESET_GEN_ROOTS=$D5_DEC effective A5=$A5"
propose RULESET_GEN_ROOTS "$D5_DEC" "$A5" "$LOGD/propose_hf7.log"
wait_cc_row "$PARAM_HF7" "$A5" "$D5_DEC" 20
[ "$CC_CB" -lt "$A5" ] || die "the RULESET_GEN_ROOTS row committed at $CC_CB, not before its effective height $A5"
cross_edge hf7 "$A5"
HF7_LINE="HF-7: rule-set generation $GEN_4 -> $GEN_5 and the head last_upd_hash seed at the end of height $(( A5 - 1 )) (param $PARAM_HF7 RULESET_GEN_ROOTS, D5 0x$D5_HEX); height $A5 is judged under generation $GEN_5"
for n in $(seq 1 "$N"); do
    grep -qF "$HF7_LINE" "$(node_log "$n")" || die "node$n logged no '$HF7_LINE' line"
    require_gen "$n" "$GEN_5" "$H4"
done
floor_diff "gen5"
echo "[ok] generation $GEN_5 on 7/7 from A5=$A5 (HF-7)"

# ── 3. hf9: four storage nodes, and segment 1 (short epoch only) ────
if [ "$WITH_STORAGE" = 0 ]; then
    # production-constant run (round-4 row 20): the four members register at generation 5 under their own keys,
    # so the registry leg (5) is populated at the edge; segments stay out of reach, so leg 6 stays empty
    for k in $MEMBERS_PRE; do register_member "$k"; done
    [ "$(sqlite3 "$(db_of 1)" "SELECT COUNT(*) FROM v2_storage_nodes WHERE status = 1;")" = 4 ] || die "the production-constant run: the registry does not hold exactly the four ACTIVE members"
fi
if [ "$WITH_STORAGE" = 1 ]; then
    # pool 1 READ FROM THE CHAIN (round-4 row 7), not from the environment the bring-up was given: below 2^17 two
    # shares round to 0 and every settlement assertion would be an all-zero pass
    POOL1_CHAIN=$(pool1_of)
    [[ "$POOL1_CHAIN" =~ ^[0-9]+$ ]] || die "pool 1 could not be read from node 1's v2_treasury ('$POOL1_CHAIN')"
    [ "$POOL1_CHAIN" -ge 131072 ] || die "pool 1 holds $POOL1_CHAIN on the chain — below 2^17 the shares round to 0 (export STAGEF_TREASURY_POOL1_RAW=1000000000000000 BEFORE stagef_up_v2.sh)"
    echo "[ok] pool 1 holds $POOL1_CHAIN on the chain (read from v2_treasury; budget per settlement = pool 1 >> $DIV_LOG2)"
    P=$(( 24 * E ))                     # DNA_V2_SEGMENT_BLOCKS
    H_PUB=$(( P + 2 * E ))              # the first storage boundary >= P + 2E
    [ $(( H_PUB % E )) = 0 ] || die "the expected publication height $H_PUB is not a boundary"
    for k in $MEMBERS_PRE; do register_member "$k"; done
    members_set $MEMBERS_PRE
    wait_all "$(tip_of 1)"
    [ "$(tip_of 1)" -lt $(( H_PUB - E )) ] || die "the members registered after $(( H_PUB - E )) — $MSG_LAYOUT (K9a would give them grace)"
    read_k9a_premise "segment-1" 1 "$H_PUB"      # at tip P + 1 (or the tip already past it), not one block before H_PUB (round 9)
    pump_to $(( H_PUB + 1 ))
    wait_all $(( H_PUB + 1 ))
    h=$(stagef_cmt_wait_row "$(db_of 1)" "SELECT COUNT(*) FROM v2_storage_segments WHERE k = 1;" 3 5) && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "segment 1 was not published on node1 by tip $h (expected at $H_PUB; wait rc $wrc)"
    stagef_sentinel TARGET_REACHED
    cell_read "segment-1" "$H_PUB" "$A5" $(( H_PUB + 1 ))
    [ "$(cell_lines seg)" = "1|$H_PUB" ] || die "the published segments are [$(cell_lines seg | tr '\n' ' ')], expected exactly segment 1 published at $H_PUB (the first storage boundary >= P + 2E)"
    reg_ok=$(cell_lines reg | awk -F'|' '$2 == 1 && $3 == 0 && $4 == 0 && $5 == 0' | wc -l)
    [ "$reg_ok" = 4 ] || die "the registry is [$(cell_lines reg | tr '\n' ' ')], expected the four members ACTIVE with exit 0, fail_streak 0, grace_until 0"
    echo "[ok] segment 1 published at $H_PUB on 7/7; four storage members ACTIVE (fail_streak 0, grace_until 0)"
    check_premise_members "segment-1" 1
    diff_full_at "$H_PUB" "segment-published-at-$H_PUB"
fi

# ── 4. hf9: populated before the edge; the param-24 vote ────────────
if [ "$WITH_STORAGE" = 1 ]; then
    pump_to $(( H_PUB + 2 ))
    wait_all $(( H_PUB + 2 ))
fi
# the attendance leg (v2_attendance_epoch) is written only by boundary processing and the first real
# boundary is DNAC_EPOCH_LENGTH itself (nodus_witness_v2_epoch.c:2196-2198, :2310-2313): reach it
# explicitly before any leg is required to be populated
if [ "$(tip_of 1)" -le "$E" ]; then
    echo "[info] tip $(tip_of 1) is before the first epoch boundary $E — pumping past it before the populated check"
    pump_to $(( E + 1 ))
    wait_all $(( E + 1 ))
fi
cell_read "pre-vote" "" 0 "$(tip_of 1)"
require_populated "pre-vote"
check_legs pre "pre-vote"
if [ "$WITH_STORAGE" = 1 ]; then
    echo "[ok] every leg's source table is populated before the vote ($(for i in 1 2 3 4 5 6 7 8; do printf 'L%s=%s ' "$i" "$(cell_one "src|$i")"; done))"
else
    echo "[ok] legs 1, 2, 3, 4, 5, 7 and 8 are populated before the vote and leg 6 (segments) is empty, as the run allows ($(for i in 1 2 3 4 5 6 7 8; do printf 'L%s=%s ' "$i" "$(cell_one "src|$i")"; done))"
fi

cc_guard 1
T_V24="$CCG_TIP"
A=$(clear_of_boundary $(( T_V24 + 1 + GRACE_SAF + A_MARGIN )))
if [ $(( A - A / E * E )) -gt $(( E - A_ROOM )) ]; then
    # round 9/10 — BOTH runs (round 10, row 11: the production branch had no rule, and clear_of_boundary excludes only
    # A % E in {0, 1} (chain_config.c:1363, :1373 exclude the boundaries A-1 and A): A % E = E-1 makes the A+1 cell
    # impossible (A+1 = B1), E-2 leaves one block). The steps between A and B1 are: the edge cell at tip >= A, the A+1
    # cell (both need tip < B1), the victim's restart (spawn + catch-up to A+2) and, in the short run, the E-s1 read; no
    # step pumps in the production run (idle blocks, 60 s each, against steps that take seconds to minutes), and the
    # short run's pump lands a few blocks above its targets. A_ROOM = 8 blocks is the distance the short run has used
    # since round 9 (E - E/2 at E 15), taken from the step count above and not from a source constant: B1 - A >= 8,
    # i.e. A % E in [2, E - 8]. At E 720 the rule moves A only when A % E is 713 .. 719 (to the next epoch + 2).
    # round-4 row 10: the report window of epoch H2 - E (the epoch settled AT B1) closes at H2 + E/2 and
    # its settlement inputs must be read before B1 = H2 + E - 1; they are read after the restart cell
    # (tip A + 2), so A + 2 has to be at most B1 - 1. A later A inside the next epoch is a layout choice (the
    # vote's effective height only has to be late enough), taken here by moving A to H2' + 2.
    A=$(( A / E * E + E + 2 ))
fi
H2_LAST=$(( A / E * E ))               # the last boundary < A (A % E >= 2 by clear_of_boundary)
B1=$(( H2_LAST + E ))                  # the first boundary >= A
[ $(( A - H2_LAST )) -ge 2 ] || die "internal: A=$A is within 1 of the boundary $H2_LAST"
echo "[ok] tip $T_V24 — node1 proposes RULESET_GEN_TRIE=$D6_DEC (D6 0x$D6_HEX) effective A=$A (A-1 and A not boundaries; H2=$H2_LAST, B1=$B1)"
propose RULESET_GEN_TRIE "$D6_DEC" "$A" "$LOGD/propose_trie.log"
wait_cc_row "$PARAM_TRIE" "$A" "$D6_DEC" 20
[ "$CC_CB" -lt "$A" ] || die "the RULESET_GEN_TRIE row committed at $CC_CB, not before its effective height $A"
floor_diff "post-d6-vote"
for n in $(seq 1 "$N"); do require_gen "$n" "$GEN_5" "$H4"; done
echo "[ok] the param-24 row is on 7/7, still generation $GEN_5 before A"

# ── 5. hf9: cross the edge idle; node 3 is down across A (restart) ───
pump_to $(( A - PUMP_STOP_GAP ))
wait_all $(( A - PUMP_STOP_GAP ))
echo "[info] idle production from tip $(tip_of 1) — nothing in flight across the edge"
# the control: still generation 5, capture 0, no trie roots, no assignment state. Round 9: read it HERE, at the lowest
# tip of the idle approach (all seven nodes alive), and not after the victim's stop at A-3, where the accepted window
# [A-3, A-2] was one block wide; here it is [A - PUMP_STOP_GAP, A - 2] (5 blocks at 7) and the cell is read
# on seven nodes. The tip is asserted <= A-2 after the read (CELL_TIP is the one tip every node was read at).
cell_read "pre-edge" "" "$A" "$(tip_of 1)"
[ "$CELL_TIP" -le $(( A - 2 )) ] || die "the pre-edge cell was read at tip $CELL_TIP, past A-2 = $(( A - 2 )) — $MSG_LAYOUT"
check_legs pre "pre-edge (tip $CELL_TIP <= A-2)"
if [ "$WITH_STORAGE" = 1 ]; then
    [ -z "$(cell_one astate)" ] || die "pre-edge: v2_storage_assign_state already has a row ('$(cell_one astate)') — the edge writes it (plan §8.6 E-s2)"
    [ -z "$(cell_lines basis)" ] || die "pre-edge: v2_storage_assign_basis is not empty"
fi
ruleset_info 1
[ "$RI_GEN" = "$GEN_5" ] || { printf '%s\n' "$RI_OUT" >&2; die "node1 reports generation '$RI_GEN' at tip $RI_TIP before the edge, expected $GEN_5"; }
[ "$RI_TIP" -le $(( A - 2 )) ] || die "ruleset-info answered at tip $RI_TIP, past A-2 = $(( A - 2 )) — $MSG_LAYOUT"
echo "[ok] before the edge (tip $CELL_TIP, ruleset-info at $RI_TIP): generation $GEN_5, capture 0, no leg roots, no assignment state, 7 live nodes"
wait_all $(( A - 3 ))
src=0; stagef_stop_node "$VICTIM" TERM || src=$?
[ "$src" != 1 ] || die "node$VICTIM is not running"
[ "$src" = 0 ] || die "stopping node$VICTIM failed (stagef_stop_node rc=$src)"
# the victim's own last applied height, read from ITS database after the stop (round-4 row 22): a restart ACROSS the
# edge needs it below A-1; nothing about the outage length is assumed
VICT_STOP_H=$(tip_of "$VICTIM")
[[ "$VICT_STOP_H" =~ ^[0-9]+$ ]] || die "node$VICTIM's last applied height is unreadable ('$VICT_STOP_H')"
[ "$VICT_STOP_H" -lt $(( A - 1 )) ] || die "node$VICTIM's last applied height after the stop is $VICT_STOP_H, not below A-1 = $(( A - 1 )) — it would not restart across the edge — $MSG_LAYOUT"
echo "[ok] node$VICTIM stopped (fleet tip $(tip_of 1), A-3 = $(( A - 3 ))); its own last applied height is $VICT_STOP_H (< A-1 = $(( A - 1 )))"
ALIVE=()
for n in $(seq 1 "$N"); do [ "$n" = "$VICTIM" ] || ALIVE+=("$n"); done

wait_all "$A"
cell_read "edge-A" "$(( A - 1 )) $A" "$A" "$A"
[ "$CELL_TIP" -ge "$A" ] || die "internal: the edge cell tip $CELL_TIP < A"
[ "$(cell_one txsum)" = 0 ] || die "edge-A: $(cell_one txsum) transaction(s) in heights $A .. $CELL_TIP — the leg roots read at $CELL_TIP would no longer be those of the end of A-1"
[ "$CELL_TIP" -lt "$B1" ] || die "edge-A: the cell was read at tip $CELL_TIP, past the first boundary $B1 — $MSG_LAYOUT"
check_legs post "edge-A (tip $CELL_TIP, no transaction since A-1)"
CELL_EDGE="$CELL"
HF9_LINE="HF-9: rule-set generation $GEN_5 -> $GEN_6, the eight keyed tries built and the dirty capture on at the end of height $(( A - 1 )) (param $PARAM_TRIE RULESET_GEN_TRIE, D6 0x$D6_HEX); height $A is judged under generation $GEN_6"
for n in "${ALIVE[@]}"; do
    grep -qF "$HF9_LINE" "$(node_log "$n")" || die "node$n logged no '$HF9_LINE' line"
done
require_gen 1 "$GEN_6" "$H4"
echo "[ok] the generation-6 edge ran at the end of A-1=$(( A - 1 )) on every live node; ruleset-info generation $GEN_6"
stagef_sentinel TARGET_REACHED
if [ "$WITH_STORAGE" = 1 ]; then
    st=$(cell_one astate)
    [ "$st" = "4|$H2_LAST|1" ] || die "edge-A: v2_storage_assign_state = '$st', expected '4|$H2_LAST|1' (R 4, boundary H2, xfer 1 — plan §8.6 E-s2)"
    members_set $MEMBERS_PRE
    [ "$(cell_lines basis | tr '\n' ' ' | sed 's/ *$//')" = "$FPS_SORTED" ] || die "edge-A: the basis is not exactly the four members"
    [ "$(cell_lines assign | awk -F'|' -v b1="$B1" '$1 == 1 && $4 == b1 && $5 == "-"' | wc -l)" = 4 ] \
        || die "edge-A: segment 1 does not have four current rows from_h = B1 = $B1 (plan §8.6 E-s2: rows from_h = B1)"
    [ "$(cell_lines assign | wc -l)" = 4 ] || die "edge-A: the assignment relation has $(cell_lines assign | wc -l) rows, expected exactly four"
    for hh in $(( H2_LAST - E )) "$H2_LAST"; do
        [ "$(cell_lines sets | awk -F'|' -v h="$hh" '$1 == h && $2 == 4' | wc -l)" = 1 ] \
            || die "edge-A: the frozen storage set of $hh does not name four members — $MSG_LAYOUT"
        [ "$(cell_lines mepoch | awk -F'|' -v h="$hh" '$1 == h' | wc -l)" -ge 1 ] \
            || die "edge-A: v2_storage_member_epoch has no row for $hh (plan §8.6 E-s1)"
    done
    echo "[ok] the storage transition ran at the edge: state (4, $H2_LAST, xfer 1), four rows from_h = B1 = $B1, member_epoch rows for $(( H2_LAST - E )) and $H2_LAST"
fi

wait_all $(( A + 1 ))
cell_read "edge-A+1" "$A $(( A + 1 ))" "$A" $(( A + 1 ))
[ "$CELL_TIP" -lt "$B1" ] || die "edge-A+1: the cell was read at tip $CELL_TIP, past the first boundary $B1"
if [ "$(cell_one txsum)" = 0 ]; then
    [ "$(cell_lines leg)" = "$(sed -n 's/^leg|//p' <<< "$CELL_EDGE")" ] \
        || die "edge-A+1: the leg roots changed between the edge cell and tip $CELL_TIP although no transaction was applied and no boundary crossed"
    echo "[ok] edge-A+1: no transaction and no boundary since A-1 — the eight leg roots are unchanged"
fi
check_legs post "edge-A+1 (tip $CELL_TIP)"

wait_all $(( A + 2 ))
stagef_spawn_node "$VICTIM" \
    || die "node$VICTIM did not come back after the restart (the [FAIL] line above names the process)"
VICT_RESTART_TIP=$(tip_of 1)
echo "[ok] node$VICTIM restarted at fleet tip $VICT_RESTART_TIP (pids $STAGEF_NODE_PIDS) — measured outage: its last applied height $VICT_STOP_H, fleet tip at the restart $VICT_RESTART_TIP, $(( VICT_RESTART_TIP - VICT_STOP_H )) block(s) behind"
for lg in "$(stagef_node_dir "$VICTIM")/nodus.log" "$(node_log "$VICTIM")"; do
    if grep -q 'REFUSING START' "$lg"; then tail -20 "$lg" >&2; die "node$VICTIM logged REFUSING START ($lg)"; fi
done
vt=$(stagef_cmt_wait_height "$(db_of "$VICTIM")" "$(( $(tip_of 1) ))" 3) \
    || die "node$VICTIM did not catch up (stuck at $vt)"
echo "[ok] node$VICTIM caught up THROUGH the edge to tip $vt"
ALIVE=()
for n in $(seq 1 "$N"); do ALIVE+=("$n"); done
wait_all "$(( A + 2 ))"
for x in $(( A - 1 )) "$A" $(( A + 1 )); do diff_full_at "$x" "edge-after-restart-at-height-$x"; done
stagef_cmt_wait_height "$(db_of 1)" "$(( A + 2 ))" 3 >/dev/null || die "node1 stalled"
cell_read "post-restart" "$(( A - 1 )) $A $(( A + 1 ))" "$A" $(( A + 2 ))
check_legs post "post-restart (tip $CELL_TIP, 7/7)"
echo "[ok] 7/7 after the restart across A: the full 64-byte global_root and block_id at A-1, A, A+1; the eight leg roots at tip $CELL_TIP"
if [ "$WITH_STORAGE" = 1 ]; then
    # round-4 row 10: the epoch H2 - E is settled AT B1 (its union counts are the edge's E-s1 values). Its reports
    # are committed in (H2, H2 + E/2]; read them now, in the window [H2 + E/2 + ..., B1 - 1], so the settlement at B1
    # is checked with the same formula as every other. The E-s1 union counts themselves are the stored values.
    if [ "$(tip_of 1)" -lt $(( H2_LAST + E / 2 )) ]; then pump_to $(( H2_LAST + E / 2 )); fi
    [ "$(tip_of 1)" -lt $(( B1 - 1 )) ] || die "the E-s1 epoch $(( H2_LAST - E )) cannot be read before B1: tip $(tip_of 1) — $MSG_LAYOUT"
    epoch_service_read $(( H2_LAST - E ))
    # (the joiner's retention restart is NOT here any more — round 6: it runs AFTER the joiner registered, see the
    # join step in section 6; a restart with an explicit retain while the node has no storage role prunes every
    # segment-2 block the guard would have kept, run 7)
fi

# ── 6. hf9: the storage assignment at B1 and its events (short epoch only) ─
if [ "$WITH_STORAGE" = 1 ]; then
    # EVENT ORDER (plan T-16: "an event case that changes no holder of the probed member" is the
    # false-pass mode — "assert at least one changed holder per case"). The order is arranged so that
    # EVERY asserted case changes a holder whatever the rendezvous scores are: a holder changes
    # deterministically when (a) the XOR relation meets four members at R 4 (B1: one member gains), (b)
    # a member leaves (its rows end), (c) a member arrives while fewer than R are eligible (it must
    # hold: every eligible member holds), (d) R rises above the holders while eligible members remain
    # without one (exactly one gains), (e) R falls below the holders (exactly one is dropped), (f) the
    # candidate crosses out (its rows end) and back (rows inserted while eligible <= R):
    #   B1            4 members {4,5,6,7}, R 4        XOR -> rendezvous: ONE member gains (n_new 1)
    #   B1+E  exit    a non-gainer of {4,5,6,7} leaves -> 3 left   its rows end; overlap retention of its file
    #   +E    arrive  the candidate -> {4,6,7,D}, R 4  D holds (3 < R)
    #   ...   D crosses OUT at its first freeze with fail_streak 3 (eligible {4,6,7})
    #   +E    join    node 2 -> {2,4,6,7}, R 4         node 2 holds (3 < R)
    #   +E    join    node 1 -> 5 live, R 4            (setup: whether node 1 holds depends on the scores;
    #                                                   only identities are asserted, no case is claimed)
    #   +2E   up      R 4 -> 5 with 5 eligible         exactly one new holder
    #   +2E   down    R 5 -> 4                          exactly one holder dropped (overlap, then deletion)
    #   +2E   up      R 4 -> 6 with 5 eligible          exactly one new holder (R now >= 6 eligible to come)
    #   ...   D crosses BACK IN (fail_streak 14 -> 0) with 6 eligible, R 6: D holds
    # Every boundary from B1 on is a cell; the reports and the settlement of every one of those epochs
    # are checked (epoch_service_read / epoch_service_post).
    CUR_B="$B1"; DEAD_FP="$D_FP"
    # round-4 row 10: the epoch H2 (the other E-s1 epoch, settled at B1 + E) joins the queue next to B1's own
    PEND_READ="$PEND_READ $H2_LAST"
    boundary_cell "B1" "$B1" 4
    # (b) the transition at B1: Σ n_new = 1, held_union 1 for all, grace B1 + E for that member
    [ "$(n_new_sum "$B1")" = 1 ] || die "B1: Σ n_new = $(n_new_sum "$B1"), expected exactly 1 (rendezvous adds one member to the three XOR holders of four, plan §8.6)"
    [ "$(cell_lines mepoch | awk -F'|' -v b="$B1" '$1 == b && $3 != 1' | wc -l)" = 0 ] || die "B1: a member has held_union != 1"
    while IFS='|' read -r _ fp _ nn; do
        want_g=0; if [ "$nn" = 1 ]; then want_g=$(( B1 + E )); fi
        [ "$(reg_grace "$fp")" = "$want_g" ] || die "B1: ${fp:0:16}… has n_new $nn and grace_until $(reg_grace "$fp"), expected $want_g (K9: B + n x E for n > 0, else 0)"
    done < <(cell_lines mepoch | awk -F'|' -v b="$B1" '$1 == b')
    [ "$(cell_lines assign | awk -F'|' '$5 == "-"' | wc -l)" = 4 ] || die "B1: the current assignment rows are not exactly four"
    echo "[ok] B1=$B1: R 4 over four members, Σ n_new = 1 (XOR -> rendezvous), grace_until B1 + E for exactly that member"
    note_new_holders "$B1"
    diff_full_at "$B1" "B1-at-height-$B1"
    require_holder_files "B1" "$B1"

    # KEY-INDEPENDENT CASES (round 7). Node identities are generated fresh in every run (key-generation randomness is
    # allowed), so WHICH of the four members the rendezvous adds at B1 changes from run to run (run 8: node 5, the
    # old fixed exiter). The two cases the plan needs (T-16: "bits for the new holders", "at least one changed holder
    # per case") must therefore be chosen FROM THE CHAIN, not by node number:
    #  * the B1 gainer = the member whose v2_storage_member_epoch row at B1 has n_new 1 (note_new_holders above put it in
    #    NEWH_AT[B1 + E]); its bit is asserted in its first eligible epoch, B1 + E, in every run;
    #  * the exiter = the lowest-numbered member of MEMBERS_PRE whose n_new at B1 is 0. At B1 all four members hold
    #    segment 1 (R 4 = four members; the current rows are asserted to be exactly four above), so every non-gainer is a
    #    current holder whose rows end at its release — the exit case holds for every key set, and the exiter is never
    #    the gainer, so the gainer is still in set(B1 + E) when its bit is read. Σ n_new = 1 (asserted at B1) leaves three
    #    candidates for the exiter; the exiter's row count is asserted below.
    GAINER=""
    for k in $MEMBERS_PRE; do
        nn=$(cell_lines mepoch | awk -F'|' -v b="$B1" -v f="${FP[$k]}" '$1 == b && $2 == f { print $4 }')
        [[ "$nn" =~ ^[0-9]+$ ]] || die "B1: node$k (${FP[$k]:0:16}…) has no v2_storage_member_epoch row at $B1"
        if [ "$nn" = 1 ]; then GAINER="$k"; elif [ "$nn" = 0 ] && [ -z "$EXITER" ]; then EXITER="$k"; fi
    done
    [ -n "$GAINER" ] && [ -n "$EXITER" ] || die "B1: could not pick a gainer (n_new 1) and an exiter (n_new 0) among the members $MEMBERS_PRE"
    [ "$(cur_rows_of "${FP[$EXITER]}")" = 1 ] || die "B1: the exiter node$EXITER does not hold segment 1 (current rows $(cur_rows_of "${FP[$EXITER]}")) — the exit case would change no holder"
    case " ${NEWH_AT[$(( B1 + E ))]:-} " in *" ${FP[$GAINER]} "*) ;; *) die "B1: the gainer node$GAINER is not queued for its bit check at epoch $(( B1 + E ))" ;; esac
    echo "[ok] B1: the rendezvous added node$GAINER (n_new 1, its bit is asserted at epoch $(( B1 + E ))); node$EXITER (n_new 0, a current holder) is the member taken out"

    # (b) the exit of node $EXITER by its owner (its own key): a holder LEAVES (rows end), release at B1 + E
    xlog="$LOGD/exit_node$EXITER.log"; xrc=0
    xport=$(stagef_tcp_port "$(dial_for "$EXITER" "$(node_keys "$EXITER")")")
    "$CLI" -s 127.0.0.1 -p "$xport" storage exit --keys "$(node_keys "$EXITER")" \
        --node-fp "${FP[$EXITER]}" --submit "127.0.0.1:$xport" > "$xlog" 2>&1 || xrc=$?
    cat "$xlog"
    [ "$xrc" = 0 ] || die "storage exit of node$EXITER by its owner exited $xrc (see $xlog)"
    grep -q '^accepted: mempool CheckTx approved' "$xlog" || die "storage exit: no CheckTx approval line (see $xlog)"
    h=$(stagef_cmt_wait_row "$(db_of "$EXITER")" \
        "SELECT COUNT(*) FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '${FP[$EXITER]}' AND status IN (2, 3) AND exit_height > 0;") && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "node$EXITER's exit did not land (wait rc $wrc, tip $h)"
    XH=$(sqlite3 "$(db_of "$EXITER")" "SELECT exit_height FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '${FP[$EXITER]}';" 2>/dev/null || echo ERR)
    [[ "$XH" =~ ^[0-9]+$ ]] && [ "$XH" -gt 0 ] || die "node$EXITER's exit_height is '$XH'"
    B_REL=$(( (XH + E - 1) / E * E ))
    [ "$B_REL" = $(( B1 + E )) ] || die "the exit landed at x=$XH, its release boundary $B_REL is not B1 + E = $(( B1 + E )) — $MSG_LAYOUT"
    echo "[ok] node$EXITER EXITING at x=$XH — release boundary B_rel=$B_REL"
    [ -f "$(seg_file "$EXITER" 1)" ] || die "node$EXITER has no seg-1.ok before its exit boundary (it held segment 1 since B1)"
    EX_DEL0=$(del_count "$EXITER" 1)
    next_boundary "B_rel" 4
    assert_file_in_overlap "T-16 exit (retention)" "$EXITER" 1 "$B_REL"
    [ "$(reg_status "${FP[$EXITER]}")" = 3 ] || die "B_rel: node$EXITER's registry status is '$(reg_status "${FP[$EXITER]}")', expected 3 (RELEASED)"
    [ "$(cur_rows_of "${FP[$EXITER]}")" = 0 ] || die "B_rel: node$EXITER still has current assignment rows"
    [ "$(cell_lines assign | awk -F'|' -v f="${FP[$EXITER]}" -v b="$B_REL" '$2 == f && $5 == b' | wc -l)" = 1 ] || die "B_rel: node$EXITER's row of segment 1 was not ended at $B_REL"
    [ "$(cell_lines assign | awk -F'|' '$1 == 1 && $5 == "-"' | wc -l)" = 3 ] || die "B_rel: segment 1 does not have three current rows (4 members minus the exiter, R 4)"
    [ "$(rows_ended "$B_REL")" = 1 ] && [ "$(rows_from "$B_REL")" = 0 ] && [ "$(n_new_sum "$B_REL")" = 0 ] \
        || die "B_rel: rows ended $(rows_ended "$B_REL"), inserted $(rows_from "$B_REL"), Σ n_new $(n_new_sum "$B_REL") — expected 1 / 0 / 0 (a holder left, the three others already hold)"
    echo "[ok] B_rel=$B_REL: node$EXITER RELEASED, out of the basis, its row ended at $B_REL (the changed holder), the three others keep theirs, no n_new"
    diff_full_at "$B_REL" "B_rel-at-height-$B_REL"
    require_holder_files "B_rel" "$B_REL"

    # ── hf9: the fail-streak crossing, both ways (plan T-13; §8.5 step 3) ──
    # A storage member that runs no node: the candidate identity cand1 (a funded genesis leaf,
    # STAGEF_V2_CANDIDATES=1). Registration has no reachability or role requirement
    # (rtn_storage_register_exec, nodus_witness_rt_native.c: owner authority, exact bond, the
    # node's consent signature, row absent or RELEASED, cap, a funding leg). A frozen-set member
    # never reachable on 0x72 is FAILed at the epoch's close ("never reachable on 0x72 … NOT OK",
    # nodus_witness_storage_reporter.c expire()); settlement adds 1 to fail_streak per epoch with
    # weight > 0 and NOT OK, not in grace and not NO_EVIDENCE, at 3 or more adds 1 every
    # settlement and writes 14 + 1 as 0 (nodus_storage_fail_streak_next, st_settle); eligibility
    # is fail_streak < 3 (DNA_V2_STORAGE_FAIL_LIMIT). next_boundary's track_d follows the counter at
    # EVERY boundary (a settlement without half the power's reports moves nothing, F1, so the
    # counter may stay; it may never skip or fall), and accepts the return to the basis only from 14.
    claim_leaf "$CAND" 1
    dlog="$LOGD/consent_cand1.txt"; drc=0
    D_EXP=$(( $(tip_of 1) + CONSENT_AHEAD ))
    "$CLI" -s 127.0.0.1 -p "$(stagef_tcp_port 1)" -i "$CAND" \
        storage consent --owner "$D_FP" --expiry "$D_EXP" --out "$dlog" > "$LOGD/consent_cand1.log" 2>&1 || drc=$?
    cat "$LOGD/consent_cand1.log"
    [ "$drc" = 0 ] && [ -s "$dlog" ] || die "the storage consent of the candidate was refused (rc $drc, see $LOGD/consent_cand1.log)"
    dport=$(stagef_tcp_port 1)
    "$CLI" -s 127.0.0.1 -p "$dport" storage register --keys "$CAND" --consent "$dlog" \
        --submit "127.0.0.1:$dport" > "$LOGD/register_cand1.log" 2>&1 \
        || { cat "$LOGD/register_cand1.log" >&2; die "storage register for the candidate failed (see $LOGD/register_cand1.log)"; }
    cat "$LOGD/register_cand1.log"
    grep -q '^accepted: mempool CheckTx approved' "$LOGD/register_cand1.log" || die "storage register for the candidate: no CheckTx approval line"
    h=$(stagef_cmt_wait_row "$(db_of 1)" \
        "SELECT COUNT(*) FROM v2_storage_nodes WHERE lower(hex(node_fp)) = '$D_FP' AND status = 1;") && wrc=0 || wrc=$?
    [ "$wrc" = 0 ] || die "the candidate's registration did not land (wait rc $wrc, tip $h)"
    BD0=$(( (h / E + 1) * E ))          # h = the tip at which the ACTIVE row was first seen
    [ $(( h % E )) != 0 ] || die "the candidate's row was first seen at tip $h, on the boundary $(( BD0 - E )) — $MSG_LAYOUT"
    [ "$BD0" = $(( B_REL + E )) ] || die "the candidate's arrival boundary is $BD0, expected B_rel + E = $(( B_REL + E )) — $MSG_LAYOUT"
    echo "[ok] the candidate ${D_FP:0:16}… (no node runs it) is a registered storage member (row seen at tip $h); its arrival boundary is $BD0"
    D_TRACK=1

    # the exiter keeps its file through the overlap epoch, then deletes it (asserted from its log below)

    # arrival: {4,6,7,D}, R 4 — three holders < R, so the candidate MUST hold: one row, n_new 1, grace B + E
    next_boundary "D-arrival" 4
    in_basis "$D_FP" || die "D-arrival: the candidate is not in the basis at $BD0"
    [ "$(rows_from "$BD0")" = 1 ] && [ "$(rows_ended "$BD0")" = 0 ] && [ "$(n_new_sum "$BD0")" = 1 ] \
        || die "D-arrival: rows inserted $(rows_from "$BD0"), ended $(rows_ended "$BD0"), Σ n_new $(n_new_sum "$BD0") — expected 1 / 0 / 1 (the new eligible member holds: 3 < R)"
    [ "$(cur_rows_of "$D_FP")" = 1 ] || die "D-arrival: the candidate does not hold segment 1"
    [ "$(reg_grace "$D_FP")" = $(( BD0 + E )) ] || die "D-arrival: the candidate's grace_until is $(reg_grace "$D_FP"), expected $(( BD0 + E ))"
    [ "$(reg_fs "$D_FP")" = 0 ] || die "D-arrival: the candidate's fail_streak is $(reg_fs "$D_FP"), expected 0"
    note_new_holders "$BD0"
    diff_full_at "$BD0" "D-arrival-at-height-$BD0"
    # deadline B_REL + 2E = the end of epoch B_REL + E (round 9 widened B_REL + E + 4; round 10 grounds it): the deleting
    # sweep runs inside epoch B_REL + E (holder.h:110 tick 200 ms, holder.c:646-661 assign at the epoch change, :369
    # sthold_gc), and assert_deleted_at below requires its logged H to be EXACTLY B_REL + E. A file that is still there at
    # tip B_REL + 2E missed that sweep — a FAIL; this is the source's own bound, not a lengthened timeout
    wait_seg_gone "$EXITER" 1 $(( B_REL + 2 * E )) || die "node$EXITER's seg-1.ok was not deleted by tip $(( B_REL + 2 * E )) although it is no holder in either epoch any more"
    assert_deleted_at "T-16 exit" "$EXITER" 1 "$EX_DEL0" $(( B_REL + E ))

    # NOT OK epochs: boundary by boundary until the first freeze with fail_streak >= 3 (the DEPARTURE)
    for _ in 1 2 3 4 5 6 7 8 9; do
        next_boundary "D-b$(( CUR_B + E ))" 4
        if [ "$D_PHASE" = out ]; then break; fi
    done
    [ "$D_PHASE" = out ] || die "the candidate (never reachable on 0x72) was still eligible after 9 boundaries (fail_streak $D_PREV) — the reports did not settle (F1) or the NOT OK path did not run"
    [ "$D_PREV" -ge 3 ] || die "D-departure: the candidate left the basis at $DEP with fail_streak $D_PREV < 3"
    [ "$(cur_rows_of "$D_FP")" = 0 ] || die "D-departure: the candidate still has current assignment rows"
    [ "$(cell_lines assign | awk -F'|' -v f="$D_FP" -v b="$DEP" '$2 == f && $5 == b' | wc -l)" = "$(cell_lines seg | wc -l)" ] \
        || die "D-departure: not every row of the candidate was ended at $DEP"
    [ "$(rows_ended "$DEP")" = 1 ] && [ "$(rows_from "$DEP")" = 0 ] && [ "$(n_new_sum "$DEP")" = 0 ] \
        || die "D-departure: rows ended $(rows_ended "$DEP"), inserted $(rows_from "$DEP"), Σ n_new $(n_new_sum "$DEP") — expected 1 / 0 / 0 (a holder left, the three others already hold)"
    diff_full_at "$DEP" "D-departure-at-height-$DEP"
    echo "[ok] D-departure: at the first freeze with fail_streak $D_PREV ($DEP) the candidate left the basis, its row ended at $DEP, the three live members keep theirs"

    # (c) join of node 2 while the candidate is out: {4,6,7} -> {2,4,6,7}, R 4 — fewer than R eligible, node 2 MUST hold
    # THE JOINER'S LAYOUT (round 6; derived from nodus_witness_role_prune.c, read to its end):
    #  * the joiner has NO retain setting until it is a registered storage member (AUTO: a bonded validator keeps
    #    everything here — nodus_witness_role_prune.c:37-49 nodus_role_prune_base, auto_blocks only when it exceeds the evidence window;
    #    the other members are archives too), so no block of segment 2 (361 .. 720) is lost while it has no role (run 7:
    #    a restart with an explicit retain BEFORE registering pruned them, role_prune.c:38-40 EXPLICIT = keep the last N);
    #  * it registers (register_member below); the registry row is ACTIVE from then, read_is_storage (role_prune.c:92-113);
    #  * THEN it is restarted with nodus.json retain_blocks N (> the evidence window). As a storage member the retain height
    #    is min(tip - N + 1, keep_from_segment, keep_from_unpublished) (role_prune.c:51-69, :356): its must-hold list
    #    is EMPTY until the next boundary (it has no assignment row at H or H - E — storage_member_ks over rows,
    #    nodus_witness_v2_storage.c:1117-1163; nodus_witness_storage_holder.c:192-205), so keep_from_segment is 0 and the
    #    guard is keep_from_unpublished = max_published_k x P + 1 = P + 1 (role_prune.c:320-326: segment 1 is the highest
    #    published). The store is therefore pruned to EXACTLY P + 1 = 361: segment 1's range (1 .. 360) is gone — the
    #    holder takes JOB_FETCH for segment 1 (holder.c:682-690, nodus_seg_store_has base <= 1 false) — while segment 2's
    #    whole range (361 .. 720) is kept (base 361 <= (2-1) x P + 1) until segment 2 is published;
    #  * this must happen BEFORE the join boundary, because the holder decides export / fetch when its job opens
    #    after the boundary: the base is asserted = P + 1 here, with a bounded pump of single blocks.
    # K9a premise (decision 2026-10-05-storage-reward-is-for-archive.md: "A segment published at boundary H is NOT
    # counted (every node holds the last 7 paydays in its block store)"): at every publication boundary every member's
    # block store holds the segment's whole range — asserted from the stores before each publication
    # (assert_members_hold_range), not assumed.
    register_member "$JOINER"
    [ "$(tip_of 1)" -lt $(( CUR_B + E - JOIN_PRUNE_MARGIN )) ] || die "the join landed at tip $(tip_of 1), fewer than $JOIN_PRUNE_MARGIN blocks before the boundary $(( CUR_B + E )) — no room for the joiner's retention restart — $MSG_LAYOUT"
    stagef_write_node_config "$JOINER" "$RETAIN_J" || die "could not write node$JOINER's nodus.json (retain_blocks $RETAIN_J)"
    src=0; stagef_stop_node "$JOINER" TERM || src=$?
    [ "$src" = 0 ] || die "stopping node$JOINER for its retention restart failed (stagef_stop_node rc=$src)"
    ALIVE=()
    for n in $(seq 1 "$N"); do [ "$n" = "$JOINER" ] || ALIVE+=("$n"); done
    stagef_spawn_node "$JOINER" || die "node$JOINER did not come back with retain_blocks $RETAIN_J (the [FAIL] line above names the process)"
    if grep -q 'REFUSING START' "$(node_log "$JOINER")"; then tail -20 "$(node_log "$JOINER")" >&2; die "node$JOINER refused to start with retain_blocks $RETAIN_J"; fi
    jt=$(stagef_cmt_wait_height "$(db_of "$JOINER")" "$(tip_of 1)" 3) || die "node$JOINER did not catch up after its retention restart (stuck at $jt)"
    ALIVE=()
    for n in $(seq 1 "$N"); do ALIVE+=("$n"); done
    echo "[ok] node$JOINER (a registered storage member) restarted with retain_blocks $RETAIN_J (evidence window $CONF_EVB blocks) and caught up to tip $jt"
    while :; do
        J_BASE=$(bs_base "$JOINER")
        [[ "$J_BASE" =~ ^[0-9]+$ ]] || die "node$JOINER's block-store base is unreadable ('$J_BASE')"
        [ "$J_BASE" -gt "$P" ] && break
        jt=$(tip_of 1)
        [ $(( jt + 1 )) -lt $(( CUR_B + E )) ] || die "node$JOINER's block store still starts at $J_BASE at tip $jt, one block before the boundary $(( CUR_B + E )) — it did not prune in time — $MSG_LAYOUT"
        pump_to $(( jt + 1 ))
        wait_all $(( jt + 1 ))
    done
    [ "$J_BASE" = $(( P + 1 )) ] || die "node$JOINER's block store starts at $J_BASE, expected exactly P + 1 = $(( P + 1 )) (the unpublished-period guard keeps segment 2's range; above it the K9a premise is broken, below it segment 1's range is still held)"
    echo "[ok] node$JOINER's block store starts at height $J_BASE = P + 1: segment 1's range (1 .. $P) is gone (nodus_seg_store_has(1) is false) and segment 2's range ($(( P + 1 )) .. $(( 2 * P ))) is kept"
    J_FETCH0=$(count_log_lines "segment 1: fetching over 0x73" "$JOINER")
    J_EXPORT0=$(count_log_lines "segment 1: exporting from this node's block store" "$JOINER")
    [ "$(tip_of 1)" -lt $(( CUR_B + E )) ] || die "the joiner's retention restart ran to tip $(tip_of 1), at or past the boundary $(( CUR_B + E )) — $MSG_LAYOUT"
    next_boundary "join-node$JOINER" 4
    [ "$(cur_rows_of "${FP[$JOINER]}")" = 1 ] && [ "$(rows_from "$CUR_B")" = 1 ] && [ "$(rows_ended "$CUR_B")" = 0 ] && [ "$(n_new_sum "$CUR_B")" = 1 ] \
        || die "join of node $JOINER: node $JOINER holds $(cur_rows_of "${FP[$JOINER]}") row(s), rows inserted $(rows_from "$CUR_B"), ended $(rows_ended "$CUR_B"), Σ n_new $(n_new_sum "$CUR_B") — expected 1 / 1 / 0 / 1 (3 holders < R: the joiner holds)"
    [ "$(reg_grace "${FP[$JOINER]}")" = $(( CUR_B + E )) ] || die "join of node $JOINER: its grace_until is $(reg_grace "${FP[$JOINER]}"), expected $(( CUR_B + E ))"
    note_new_holders "$CUR_B"
    diff_full_at "$CUR_B" "join-node$JOINER-at-height-$CUR_B"
    require_holder_files "join-node$JOINER" "$CUR_B"
    # the fetch path RAN on the joiner: its holder runtime logged the fetch line (and no export line) for
    # segment 1 and the file is there (require_holder_files above waited for seg-1.ok to a tip below the next boundary)
    [ "$(count_log_lines "segment 1: fetching over 0x73" "$JOINER")" -gt "$J_FETCH0" ] || die "join of node $JOINER: no 'segment 1: fetching over 0x73' line in its log — the fetch path did not run"
    [ "$(count_log_lines "segment 1: exporting from this node's block store" "$JOINER")" = "$J_EXPORT0" ] || die "join of node $JOINER: it EXPORTED segment 1 from its block store although the store was pruned"
    [ -f "$(seg_file "$JOINER" 1)" ] || die "join of node $JOINER: the fetch line is logged but $(seg_file "$JOINER" 1) does not exist"
    echo "[ok] join of node $JOINER at $CUR_B: it holds segment 1 whatever the scores (3 < R 4); one holder changed; its holder runtime FETCHED segment 1 over 0x73 (block store from $J_BASE) and its marker seg-1.ok is present (the pruned joiner's probes are answered from the file, which is what exercises it)"

    # setup: node 1 joins too (5 live eligible, R 4): whether it holds depends on the scores — only the
    # generic invariants and the identities rows inserted = rows ended = Σ n_new are asserted
    register_member 1
    [ "$(tip_of 1)" -lt $(( CUR_B + E )) ] || die "node 1's join landed at tip $(tip_of 1), at or past the boundary $(( CUR_B + E )) — $MSG_LAYOUT"
    next_boundary "join-node1" 4
    [ "$(n_new_sum "$CUR_B")" = "$(rows_from "$CUR_B")" ] && [ "$(rows_ended "$CUR_B")" = "$(rows_from "$CUR_B")" ] \
        || die "join of node 1: Σ n_new $(n_new_sum "$CUR_B"), rows inserted $(rows_from "$CUR_B"), ended $(rows_ended "$CUR_B") — expected all equal (4 holders of 5 before and after)"
    note_new_holders "$CUR_B"
    diff_full_at "$CUR_B" "join-node1-at-height-$CUR_B"
    require_holder_files "join-node1" "$CUR_B"

    # (d) copies UP 4 -> 5 with five eligible and four holders: EXACTLY ONE member gains
    vote_copies 5
    copies_boundaries 4 5 "copies-up-5"
    [ "$(rows_from "$CUR_B")" = 1 ] && [ "$(rows_ended "$CUR_B")" = 0 ] && [ "$(n_new_sum "$CUR_B")" = 1 ] \
        || die "copies 4 -> 5: rows inserted $(rows_from "$CUR_B"), ended $(rows_ended "$CUR_B"), Σ n_new $(n_new_sum "$CUR_B") — expected 1 / 0 / 1 (the one eligible member without a row gains)"
    [ "$(cell_lines assign | awk -F'|' '$1 == 1 && $5 == "-"' | wc -l)" = 5 ] || die "copies 4 -> 5: segment 1 does not have five current rows"
    note_new_holders "$CUR_B"
    diff_full_at "$CUR_B" "copies-up-5-at-height-$CUR_B"
    require_holder_files "copies-up-5" "$CUR_B"
    echo "[ok] copies 4 -> 5 at $CUR_B: five current rows, exactly one new holder"

    # (e) copies DOWN 5 -> 4: EXACTLY ONE holder is dropped; its file is kept through the overlap
    # epoch and deleted after it; it keeps its bit in the overlap epoch and has none after
    vote_copies 4
    copies_boundaries 5 4 "copies-down-4"
    [ "$(rows_ended "$CUR_B")" = 1 ] && [ "$(rows_from "$CUR_B")" = 0 ] && [ "$(n_new_sum "$CUR_B")" = 0 ] \
        || die "copies 5 -> 4: rows ended $(rows_ended "$CUR_B"), inserted $(rows_from "$CUR_B"), Σ n_new $(n_new_sum "$CUR_B") — expected 1 / 0 / 0 (one holder dropped)"
    [ "$(cell_lines assign | awk -F'|' '$1 == 1 && $5 == "-"' | wc -l)" = 4 ] || die "copies 5 -> 4: segment 1 does not have four current rows"
    DROP_B="$CUR_B"
    DROP_FP=$(cell_lines assign | awk -F'|' -v b="$DROP_B" '$5 == b { print $2 }')
    DROP_NODE=$(fp_node "$DROP_FP")
    [ -n "$DROP_NODE" ] || die "copies 5 -> 4: the dropped holder ${DROP_FP:0:16}… is no harness node"
    ZERO_AT[$(( DROP_B + E ))]="${ZERO_AT[$(( DROP_B + E ))]:-} $DROP_FP"
    # retention of the DROPPED node's file, from the file itself at a tip inside the overlap epoch (round-4 row 11)
    assert_file_in_overlap "T-16 drop (retention)" "$DROP_NODE" 1 "$DROP_B"
    diff_full_at "$DROP_B" "copies-down-4-at-height-$DROP_B"
    require_holder_files "copies-down-4" "$DROP_B"
    DROP_DEL0=$(del_count "$DROP_NODE" 1)
    echo "[ok] copies 5 -> 4 at $DROP_B: node $DROP_NODE dropped (the changed holder)"
    next_boundary "drop+E" 4
    wait_seg_gone "$DROP_NODE" 1 $(( DROP_B + 2 * E )) || die "node $DROP_NODE's seg-1.ok was not deleted by tip $(( DROP_B + 2 * E )) after the overlap epoch (the sweep of epoch $(( DROP_B + E )), one epoch of liveness bound)"
    assert_deleted_at "T-16 drop" "$DROP_NODE" 1 "$DROP_DEL0" $(( DROP_B + E ))

    # (f) copies UP 4 -> 6 with five eligible: the dropped member (or the other without a row) gains — so that when
    # the candidate returns, six are eligible with R 6 and the candidate MUST hold
    vote_copies 6
    copies_boundaries 4 6 "copies-up-6"
    [ "$(rows_from "$CUR_B")" = 1 ] && [ "$(rows_ended "$CUR_B")" = 0 ] && [ "$(n_new_sum "$CUR_B")" = 1 ] \
        || die "copies 4 -> 6: rows inserted $(rows_from "$CUR_B"), ended $(rows_ended "$CUR_B"), Σ n_new $(n_new_sum "$CUR_B") — expected 1 / 0 / 1"
    [ "$(cell_lines assign | awk -F'|' '$1 == 1 && $5 == "-"' | wc -l)" = 5 ] || die "copies 4 -> 6: segment 1 does not have five current rows"
    note_new_holders "$CUR_B"
    diff_full_at "$CUR_B" "copies-up-6-at-height-$CUR_B"
    require_holder_files "copies-up-6" "$CUR_B"

    # the candidate's RETURN: boundary by boundary until it is back in the basis (fail_streak 14 -> 0,
    # accepted by track_d only after every settlement +1 up to 14)
    for _ in $(seq 1 20); do
        if [ "$D_PHASE" = back ]; then break; fi
        [ $(( CUR_B + E - DEP )) -le $(( 20 * E )) ] || die "the candidate was still out of the basis 20 epochs after its departure (fail_streak $D_PREV) — the K5 return did not complete"
        next_boundary "D-b$(( CUR_B + E ))" 6
    done
    [ "$D_PHASE" = back ] || die "the candidate was still out of the basis after 20 more boundaries (fail_streak $D_PREV) — the K5 return (3 + 12 skipped epochs) did not complete"
    # The inserts of this boundary are of TWO kinds (round-4 row 17): the PUBLICATION inserts of a segment
    # published AT $REV (from_h = REV, one row per holder over the six eligible: min(R 6, |basis|) rows, no
    # n_new — K9a: a segment published after REV - E gives no count) and the REVIVAL inserts of the candidate
    # for every segment published <= REV - E (one row each, n_new 1 each). They are counted apart.
    NSEG=$(cell_lines seg | wc -l)
    NOLD=$(cell_lines seg | awk -F'|' -v c="$(( REV - E ))" '$2 <= c' | wc -l)
    NPUB=$(cell_lines seg | awk -F'|' -v r="$REV" '$2 == r' | wc -l)
    [ $(( NOLD + NPUB )) = "$NSEG" ] || die "D-revival: $NSEG published segment(s), $NOLD published <= $(( REV - E )), $NPUB published at $REV — a segment lies strictly between (boundaries are multiples of E: the relation is corrupt)"
    NBASIS=$(cell_lines basis | wc -l)
    WANT_PUB=$(( NPUB * (6 < NBASIS ? 6 : NBASIS) ))
    [ "$(cur_rows_of "$D_FP")" = "$NSEG" ] || die "D-revival: the candidate has $(cur_rows_of "$D_FP") current rows, expected one per published segment = $NSEG (6 eligible, R 6: it MUST hold)"
    [ "$(rows_from "$REV")" = $(( NOLD + WANT_PUB )) ] && [ "$(rows_ended "$REV")" = 0 ] && [ "$(n_new_sum "$REV")" = "$NOLD" ] \
        || die "D-revival: rows inserted $(rows_from "$REV"), ended $(rows_ended "$REV"), Σ n_new $(n_new_sum "$REV") — expected $(( NOLD + WANT_PUB )) ($NOLD revival + $WANT_PUB publication) / 0 / $NOLD"
    [ "$(cell_lines mepoch | awk -F'|' -v b="$REV" -v f="$D_FP" '$1 == b && $2 == f { print $4 }')" = "$NOLD" ] \
        || die "D-revival: the candidate's n_new is not the $NOLD segment(s) it did not hold that were published <= $(( REV - E )) (K9a)"
    if [ "$NOLD" -gt 0 ]; then
        [ "$(reg_grace "$D_FP")" = $(( REV + NOLD * E )) ] || die "D-revival: the candidate's grace_until is $(reg_grace "$D_FP"), expected $(( REV + NOLD * E ))"
    fi
    note_new_holders "$REV"
    diff_full_at "$REV" "D-revival-at-height-$REV"
    require_holder_files "D-revival" "$REV"
    echo "[ok] D-revival at $REV: fail_streak 14 -> 0, back in the basis (6 eligible, R 6), $NOLD revival row(s) + $WANT_PUB publication row(s) inserted, 7/7"

    # the epochs of the return: boundary by boundary until the epoch of EVERY queued new-holder and
    # dropped-holder check (NEWH_AT / ZERO_AT keys) has been a cell (round-4 row 18: with two or more
    # segments the candidate's grace ends at REV + NSEG x E and its first eligible epoch lies later than
    # the old fixed REV + E), then every queued report window and settlement is served
    LAST_KEY="$CUR_B"
    for key in "${!NEWH_AT[@]}" "${!ZERO_AT[@]}"; do
        if [ "$key" -gt "$LAST_KEY" ]; then LAST_KEY="$key"; fi
    done
    while [ "$CUR_B" -lt "$LAST_KEY" ]; do next_boundary "after-revival" 6; done
    next_boundary "after-revival-last" 6
    drain_pending
    echo "[ok] every queued report window and settlement was served up to tip $(tip_of 1) (reads pending: '${PEND_READ# }'; settlements pending: '${PEND_POST# }')"
fi

# ── 7. hf9: a fresh node replaying from genesis ─────────────────────
vnd=$(stagef_node_dir "$VICTIM")
vlog=$(stagef_node_log "$VICTIM")
src=0; stagef_stop_node "$VICTIM" KILL || src=$?
[ "$src" = 0 ] || die "stopping node$VICTIM for the wipe failed (stagef_stop_node rc=$src)"
ALIVE=()
for n in $(seq 1 "$N"); do [ "$n" = "$VICTIM" ] || ALIVE+=("$n"); done
sleep 3
rm -f "$vnd/data/"*.db "$vnd/data/"*.db-wal "$vnd/data/"*.db-shm \
      "$vnd/data/.witness_db_seen" "$vnd/data/.bootstrap_in_progress" \
      "$vnd/data/.recovery_in_progress"
rm -rf "$vnd/data/archive" "$vnd/data/segments"
# the logs of node $VICTIM before the wipe are KEPT (and scanned at the end): a shadow fault logged
# before the wipe must not disappear with the truncation
PREWIPE_LOGS="$LOGD/node${VICTIM}_prewipe_nodus.log"
cp "$vnd/nodus.log" "$PREWIPE_LOGS"
if [ "$vlog" != "$vnd/nodus.log" ]; then
    cp "$vlog" "$LOGD/node${VICTIM}_prewipe_witness.log"
    PREWIPE_LOGS="$PREWIPE_LOGS $LOGD/node${VICTIM}_prewipe_witness.log"
fi
: > "$vnd/nodus.log"
[ "$vlog" = "$vnd/nodus.log" ] || : > "$vlog"
ls "$vnd/data/"witness_*.db >/dev/null 2>&1 && die "the wipe did not remove node$VICTIM's chain DB"
echo "[ok] node$VICTIM wiped (identity kept, databases and logs gone)"
fleet_chain=$(basename "$(db_of 1)")
stagef_spawn_node "$VICTIM" --v2-genesis-pin "$PIN" \
    || die "node$VICTIM did not come up after the wipe (the [FAIL] line above names the process)"
# the adoption wait is bounded by BLOCK DISTANCE (the fleet's tip may rise by 3 blocks, 3 idle intervals,
# before node $VICTIM has created its chain database) AND by PROGRESS (round-4 row 15): a fleet tip that does not
# rise for 3 CreateEmptyBlocks intervals is a stalled chain, a FAIL — never an endless wait
adopt_t0=$(tip_of 1); adopt_last="$adopt_t0"; adopt_since=0; adopt_stall=$(( 3 * STAGEF_CMT_EMPTY_INTERVAL_MS / 1000 ))
while :; do
    if ls "$vnd/data/"witness_*.db >/dev/null 2>&1 && [ -n "$(db_of "$VICTIM")" ]; then break; fi
    adopt_t=$(tip_of 1)
    if [ "$adopt_t" -ge $(( adopt_t0 + 3 )) ]; then
        tail -30 "$vlog" >&2; die "node$VICTIM never adopted a chain while the fleet moved from $adopt_t0 to $adopt_t"
    fi
    if [ "$adopt_t" -gt "$adopt_last" ]; then adopt_last="$adopt_t"; adopt_since=0; else adopt_since=$(( adopt_since + 1 )); fi
    if [ "$adopt_since" -ge "$adopt_stall" ]; then
        tail -30 "$vlog" >&2; die "node$VICTIM adopted no chain and the fleet's tip made no progress for $adopt_stall s (3 idle intervals) at $adopt_t — a stalled chain"
    fi
    sleep 1
done
[ "$(basename "$(db_of "$VICTIM")")" = "$fleet_chain" ] || die "node$VICTIM adopted a DIFFERENT chain than the fleet's"
fleet_tip=$(tip_of 1)
vt=$(stagef_cmt_wait_height "$(db_of "$VICTIM")" "$fleet_tip" 3) \
    || die "node$VICTIM adopted the chain but did not replay to the fleet tip $fleet_tip (stuck at $vt)"
echo "[ok] node$VICTIM replayed from genesis to tip $vt (fleet tip was $fleet_tip)"
ALIVE=()
for n in $(seq 1 "$N"); do ALIVE+=("$n"); done
# the replay crossed the edges: its log was truncated, so these lines are of THIS replay
grep -qF "$HF7_LINE" "$vlog" || die "the replaying node$VICTIM logged no '$HF7_LINE' line — it did not replay the generation-5 edge"
grep -qF "$HF9_LINE" "$vlog" || die "the replaying node$VICTIM logged no '$HF9_LINE' line — it did not replay the generation-6 edge"
echo "[ok] node$VICTIM's replay logged the generation-5 and the generation-6 edge lines"
wait_all "$vt"
for x in $(( A - 1 )) "$A" $(( A + 1 )) "$vt"; do diff_full_at "$x" "replay-at-height-$x"; done
cell_read "post-replay" "$(( A - 1 )) $A $(( A + 1 ))" "$A" "$vt"
check_legs post "post-replay (tip $CELL_TIP, 7/7)"
if [ "$WITH_STORAGE" = 1 ]; then
    st=$(cell_one astate)
    IFS='|' read -r pr_copies pr_b _ <<< "$st"
    [ "$pr_copies" = 6 ] || die "post-replay: v2_storage_assign_state.copies = '$pr_copies', expected 6 (the last STORAGE_COPIES vote)"
    check_storage_state "$pr_b" 6 "post-replay"
    in_basis "$D_FP" || die "post-replay: the revived candidate is not in the basis"
    [ "$(cur_rows_of "$D_FP")" = "$(cell_lines seg | wc -l)" ] || die "post-replay: the candidate does not hold one row per published segment"
    echo "[ok] post-replay: the replayed node holds the same storage relations (R 6, the revived candidate back, every table byte-identical to the six others)"
fi
stagef_sentinel ASSERT_RUN
floor_diff "post-hf9"

# ── 8. no fault line anywhere ───────────────────────────────────────
# grep's exit status is read: 0 = match (a FAIL), 1 = no match (the only passing answer), anything else = the
# log could not be read, which is a FAIL and never "no match" (round-4 row 19)
for lg in $(for n in $(seq 1 "$N"); do node_log "$n"; done) $PREWIPE_LOGS; do
    [ -f "$lg" ] && [ -r "$lg" ] || die "the log $lg cannot be read — the no-fault scan would prove nothing"
    for fault in 'HF9-SHADOW FAULT' 'CMT_FAULT'; do
        grc=0; grep -q -- "$fault" "$lg" || grc=$?
        case "$grc" in
            0) grep -- "$fault" "$lg" | tail -3 >&2; die "$lg holds a '$fault' line$([ "$fault" = 'HF9-SHADOW FAULT' ] && echo ' (plan §11)')" ;;
            1) ;;
            *) die "grep of '$fault' in $lg failed (rc $grc) — an unreadable log is not a clean log" ;;
        esac
    done
done
echo "[ok] no node log — node $VICTIM's pre-wipe copies included — holds an HF9-SHADOW FAULT or a CMT_FAULT"

stagef_sentinel PASS
echo ""
echo "[info] HEIGHTS: HF2 $H2 | HF3 $H3 | GEN2 $H4 | EVM $HE | ROLES $H6 | ROOTS $A5 | TRIE (A) $A | H2 $H2_LAST | B1 $B1"
if [ "$WITH_STORAGE" = 1 ]; then
    echo "       | segment 1 at $H_PUB | exit x=$XH released $B_REL | candidate arrival $BD0, departure $DEP, return $REV | last cell $CUR_B"
    echo "[PASS] HF-9 generation 6 at E=$E, BPY $CONF_BPY, SAFETY grace $GRACE_SAF, ERGONOMIC grace $GRACE_ERG (7/7 at epoch length $E):"
    echo "       populated legs, D6 voted at A=$A, the edge at the end of A-1. Leg roots: at A-1, A, A+1 read from a window with no"
    echo "       envelope and no boundary, byte-identical on 7/7; at B1, B1+E, B1+2E and every later boundary only the full global_root"
    echo "       and block_id AT the height (7/7) plus the leg roots of one snapshot at a LATER tip (per-height comparison NOT covered)."
    echo "       The storage relations are byte-identical on 7/7 at every boundary from B1 to $CUR_B; every case changed a holder (B1 transition, exit,"
    echo "       arrival, candidate out and back, join, copies up / down / up) with its report bits (answers its probes),"
    echo "       overlap retention (the dropped files seen inside the overlap epoch) and the deletion heights; the joiner node $JOINER"
    echo "       FETCHED segment 1 over 0x73 (block store from $J_BASE). Exact: grace_until, fail_streak and (after B1) held_union /"
    echo "       n_new at every boundary; every epoch queued from B1 on, and the two epochs settled at B1 and B1+E, was read in"
    echo "       its report window and its settlement amounts checked against the source formula (pool 1 read from the chain,"
    echo "       a positive share in every paying epoch); no check is pending. node $VICTIM (last applied height $VICT_STOP_H, fleet"
    echo "       tip $VICT_RESTART_TIP at its restart) restarted across A and replayed from genesis."
    echo "       NOT COVERED: leg roots PER HEIGHT at B1, B1+E, B1+2E (only the full global root at the height, and the leg roots at a"
    echo "       later tip); a running member's holder runtime across the eligibility crossing (the candidate runs no node); the"
    echo "       E-s1 union counts and held_union / n_new at B1 derived independently (XOR relation); the settlement of payday"
    echo "       boundaries; any NOT OK by a wrong answer (unit tests)."
else
    echo "[PASS] HF-9 generation 6 at E=$E, BPY $CONF_BPY, SAFETY grace $GRACE_SAF, ERGONOMIC grace $GRACE_ERG WITHOUT storage"
    echo "       segments (production-constant edge run; test parameters chosen by the orchestrator — the production 17280"
    echo "       safety grace is NOT exercised): legs 1, 2, 3, 4, 5 (the four registered storage members), 7, 8 populated and leg 6"
    echo "       (segments) EMPTY (source table 0 rows, root = the empty-leg root), D6 voted at A=$A, the edge at the end of A-1,"
    echo "       eight leg roots at A-1, A, A+1 (a window with no envelope and no boundary) byte-identical on 7/7, node $VICTIM (last applied height $VICT_STOP_H, fleet tip $VICT_RESTART_TIP at its"
    echo "       restart) restarted across A and then replayed from genesis. LEFT OUT: segment 1 (P = 24 x E is out of reach), B1,"
    echo "       every storage event, param 25, the candidate, the settlements."
fi
