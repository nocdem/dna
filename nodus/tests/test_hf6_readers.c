/**
 * @file nodus/tests/test_hf6_readers.c
 * @brief HF-6 sub-slice 3d — the boundary and root readers under the
 *        generation-4 keys: the §6.3 / §6.4 leaves, the distribution's
 *        v1-snapshot bridge with earnings to the owner, the graduation to
 *        the owner, the committee by validator_id, and an inventory of
 *        every SQL reader of `validators` / `delegations` in the boundary
 *        and root files.
 *
 * Design docs/plans/2026-10-03-hf5-validator-owner-stake-design.md rev 6
 * §1.6 (base + commission to owner_fp), §6.3 / §6.4 (leaf v2 bytes,
 * approved), §7.2 (RETIRING graduates to owner_fp, Q4 = a), §7.4 (copy
 * re-keyed, amounts untouched), §7.5 (v1-snapshot bridge), §7.8 (the
 * validator_id tiebreak is slice 5's — slice 3 keeps pubkey); plan
 * tasks/hf6-slice3-plan.md §2 "3d", §3, §4; decisions docs/plans/
 * decisions/2026-10-08-kurultay-14-hf6-summary.md (K2, K4, K8) and
 * 2026-10-09-kurultay-16-hf6-storage-summary.md (D2: the Foundation rows
 * are exactly active_since_block <= 1).
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. leaf_bytes (direct, a hand-built DB migrated by
 *     nodus_witness_v2_roles_migrate inside a transaction the test owns):
 *     the §6.3 body of three migrated rows (Foundation-owned ACTIVE,
 *     own-owner ELIGIBLE with distinct pending / update / missed values,
 *     Foundation-owned RETIRING with an unstake_commit_block) equals the
 *     test's own restatement of the §6.3 table, offset by offset; the
 *     validator root v2 equals the test's RFC 6962 root over
 *     SHA3-512(0x02 ‖ body) in validator_id order; the delegation root v2
 *     likewise over SHA3-512(0x03 ‖ delegator_fp ‖ validator_id ‖ amount ‖
 *     at) in (validator_id, delegator_fp) order; 1 + 5389 = 5390 and
 *     1 + 144 = 145; a missing roles row, an orphan roles row and a
 *     pre-migration database (no roles rows) FAIL the validator root; the
 *     empty tables give the tagged sentinels.
 *  B. engine_foundation (twin seeded GEN_STORAGE chains, seven real-key
 *     validators all active_since 1 — so all Foundation-owned after the
 *     gen-4 edge at block H14−1 — plus a RETIRING Foundation row VR with a
 *     3M delegation from KR, and KD delegating 4M to V0; every block from
 *     2 carries the seven COMMIT votes; reward pool 10^16):
 *     - after block H14−1 the registry is generation 4 and the committed
 *       SYSTEM head equals the runtime's recomputation (v5 over the v2
 *       leaves);
 *     - boundaries E, 2E, 3E (governed by snapshots built from the PRE-H
 *       copy(0), self_bond 10M) and 4E (the first one from the POST-H
 *       copy(E), self_bond 2M, an 8M kind-1 row owned by the Foundation
 *       per member) each APPLY (the consistency gate holds — a mismatch
 *       would FAULT the block) and move every accrual by EXACTLY the
 *       test's restatement of the split: base + commission to the row's
 *       owner_fp (the compiled Foundation owner), x_d to each copy row's
 *       owner (the Foundation's 8M row, KD's 4M row); the pool is debited
 *       by exactly Σ; no validator's node-key fp ever holds an accrual;
 *     - at E the RETIRING row graduates: its 10M bond becomes a UTXO owned
 *       by hex(Foundation owner), KR's 3M a UTXO owned by hex(SHA3(KR)),
 *       Σ released == self_stake + total_delegated read before, the row
 *       is UNSTAKED with zero amounts and no delegation names it;
 *     - snapshots 2E..5E (built by the gen-4 committee) hold exactly the
 *       seven genesis pubkeys; the ones built from a post-H copy carry
 *       self_bond 2M and total 10M (V0: 14M);
 *     - after every block the twins' committed global roots are equal,
 *       and at the end the two databases are byte-identical
 *       (v2x_db_digest).
 *  C. engine_own_owner (one seeded chain, V6 active_since 2 — so its
 *     owner is SHA3-512(its pubkey), D2): the same per-boundary
 *     restatement over E..4E; at E V6's own fp is credited; at 4E V6 is a
 *     member of snapshot(3E) and both its base and its own 8M
 *     self-delegation share land on its own fp.
 *  D. reader_inventory: every string-literal SQL reference to
 *     `validators` / `delegations` (FROM / UPDATE / INTO / JOIN) and every
 *     call of a pubkey-keyed CRUD function in the boundary / root files
 *     sits in a function the pinned table classifies, with exactly the
 *     pinned count; every function classified ARMED contains a
 *     NODUS_RT_GEN_STORAGE test; every GEN4_ONLY function is called from
 *     an ARMED caller.
 *  E. engine_v2_snapshot (HF-6 slice 5c, re-based on 5d; plan tasks/
 *     hf6-slice5-plan.md §2 "5c"; design §1.6, §5 "Ödül", §7.5; decision
 *     2026-10-08-kurultay-14 K2; ORCHESTRATOR D6). One seeded chain of
 *     fixture B's shape (no RETIRING row) driven to 5E − 1; the boundary
 *     is 5E, its governing snapshot(4E) (built at 3E from the post-H
 *     copy(2E)). Since 5d every snapshot this chain builds after its edge
 *     (B₀ = E, so snapshot(2E) on) is the engine's own RULESET 2:
 *     E1 the gen-4 core re-selects for 5E exactly the stored snapshot(5E)
 *        — RULESET 2 — and every member carries its row's validator_id /
 *        owner_fp, which are the stored entries' too; the entry fill of
 *        the members hashes to the stored hash; get_for_block returns
 *        the ids ZERO on a miss and on the following hit (hit == miss);
 *     E2 a copy of snapshot(4E) whose one entry's owner_fp is not its
 *        row's → settlement_apply −2;
 *     E3 the stored snapshot paid with key generation 3 → −2 (a ruleset-2
 *        snapshot below generation 4 is a broken invariant);
 *     E4 an entry whose validator_id names NO row (its copy(2E) rows
 *        re-keyed to it so the gate holds) → applied, that member unpaid
 *        (its share stays in the pool), every other delta exact;
 *     E5 K2: V0 raised to 60M whole coins (+ a 46M copy(2E) delegation),
 *        the rest 10M → counted [25714285, 10M × 6] (dna_power_cap_
 *        counted, and the witness helper over the stored row agrees);
 *        shares by counted / Σcounted, V0's split on its raw 60M — every
 *        delta exact;
 *     E6 an UNSTAKED row holding V1's consensus pubkey under its own id
 *        (the by-pubkey read that FAULTED on it, slice-4 fault 2, is
 *        deleted — no production caller); with snapshot(4E) rewritten in its ruleset-1 shape (the v1 governing
 *        snapshot a post-H boundary still reads — case F crosses the real
 *        one) the ruleset-1 bridge (v2_get of the migrated id) pays
 *        exactly;
 *     E7 THROUGH THE ENGINE: the engine's own ruleset-2 snapshot(4E) and
 *        the UNSTAKED twin row committed, block 5E applies; base +
 *        commission to entry.owner_fp (the Foundation owner) by
 *        validator_id, KD's delegation share to KD, nobody else, no
 *        node-key accrual.
 *     E2..E6 call nodus_witness_v2_settlement_apply directly inside a
 *     transaction that is always rolled back.
 *  F. engine_switch (HF-6 slice 5d; plan §1 "Which boundary writes the
 *     first v2 snapshot", §2 "5d"; design §7.7 item 8 — the khan's
 *     tiebreak decision 2026-10-12 —, §5, §8; ORCHESTRATOR D4). Twin
 *     seeded chains of fixture B's shape without the RETIRING row, plus a
 *     genesis delegation KB → V0 of 46M (V0 = 10M + KD 4M + KB 46M = 60M,
 *     the others 10M); H = H14, B₀ = the first multiple of E above it = E;
 *     driven to B₀ + 2E:
 *     F1 snapshot(0) and snapshot(B₀) are ruleset 1 and boundary B₀ leaves
 *        their hashes unchanged; generation 4 is in force before B₀;
 *     F2 snapshot(B₀+E), stored by B₀, is RULESET 2 on both twins; its
 *        seven ids are the migrated ids naming the roles rows (owner the
 *        Foundation, same consensus key); V0 first at 60M; the six equal
 *        10M seats in SHA3-512(0x02 ‖ validator_id ‖ seed) ASC, the
 *        129-byte preimage built here, seed = the v2_blocks BlockID at
 *        B₀ − 1;
 *     F3 (§12g under ruleset 2) preview_next(B₀, generation 4) over the
 *        post-boundary state encodes to exactly the stored blob and hash;
 *     F4 the Comet update at B₀+E RESTATED (see HOW IT CAN LIE): both
 *        sides' powers through nodus_witness_vset_powers, matched by
 *        pubkey — new counted [25714285, 10M × 6] (= the shared/dnac cap
 *        over the entries), old raw [60000000, 10M × 6]; exactly ONE
 *        power change (V0), no addition, no removal;
 *     F5 the distribution at B₀+E (governed by the v1 snapshot(B₀) via
 *        the migrated-id bridge, raw power) and the FIRST v2-governed one
 *        at B₀+2E (snapshot(B₀+E), by validator_id, counted / Σcounted,
 *        base + commission to entry.owner_fp) each move every accrual by
 *        exactly the restated amount on both twins (Foundation, KD, KB;
 *        nobody else; no node-key row); snapshot(B₀+2E), (B₀+3E) are
 *        ruleset 2;
 *     the twins' global roots agree after every block and the databases
 *     are byte-identical at the end.
 *  G. codec_inventory (HF-6 5d): the identifiers of every function body
 *     of nodus_witness_vset.c contain none of dna_vset_hash /
 *     dna_vset_decode / dna_vset_encode / dna_vset_hash_bytes /
 *     dna_vset_encoded_len (the ruleset-1-only entry points), and do
 *     contain the `_ex` hash / decode / encode (positive control).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: NODUS_EVM_ENABLED (generation 4 exists only there; the
 * target is registered only then) and NODUS_HF6_READERS_SRC_DIR (the
 * witness source directory, set by CMake — D reads the sources). Heights
 * derive from DNAC_EPOCH_LENGTH (>= 8 checked); the chain's payout
 * interval must be >= 5 epochs (checked — a payday inside 1..4E would
 * empty the accrual table under the deltas). B/C assert the compiled
 * DNAC_HF6_FOUNDATION_OWNER whatever it is (a test-build override is
 * honoured). Environment: none. Cost: B applies 4E blocks to each of two
 * fixtures and C 4E to one, E 5E − 1 + 1 to one, F 3E to each of two —
 * 16,560 block applications at E = 720. E also needs a payout interval
 * >= 6 epochs, F >= 4 (checked). F and G read the sources' and the
 * fixture's shape only through NODUS_HF6_READERS_SRC_DIR (G) and H14 < E
 * (F, checked).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf6_readers_* directory per fixture, removed at its end
 * (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - B/C's expected split is the test's RESTATEMENT of the distribution
 *    (design §7.1 + §1.6) read from the same snapshot and copy rows the
 *    engine reads — it proves where the money goes and that the gate
 *    holds, not that the restated formula is the right economics. It
 *    assumes every member meets the attendance bar (all seven vote every
 *    block); a member that did not would make the check fail, not pass.
 *  - The genesis is seeded (v2_genesis_fixture.h "HOW IT CAN LIE"),
 *    carries a non-zero reward pool (the test_v2_econ device) and a
 *    RETIRING row (V2X_SEED_NOT_REAL_STATUSES).
 *  - A's leaf restatement is self-consistent with the approved §6.3 /
 *    §6.4 tables, not an independent oracle's vectors.
 *  - E2/E4/E5/E6's snapshots are decoded copies of the engine's stored
 *    row, MUTATED and written back by direct SQL inside a rolled-back
 *    transaction (E6's is the ruleset-1 shape of a ruleset-2 row), and
 *    the restatement (expect_snap) is the test's own — like B/C's, it
 *    proves the routing and the arithmetic against the design's rule, not
 *    the economics. E4's "no row" entry and E6's UNSTAKED twin are states
 *    no chain reaches (states the resolution must survive, not ones it
 *    produced). Since 5d every block from 2E on is GOVERNED by a ruleset-2
 *    snapshot in B, C, E and F — the per-block phase 0a hash
 *    (nodus_witness_v2_apply.c, dna_vset_hash_ex) is exercised by every
 *    one of them.
 *  - F4 does NOT run nodus_witness_cmt_app.c's FinalizeBlock diff: the
 *    host (v2x_cmt_apply) drives the engine only. It restates the diff —
 *    the same helper on the same two stored snapshots, matched by pubkey
 *    as that loop matches. A diff loop that stopped calling the helper
 *    would stay green here (test_cmt_app.c pins the loop).
 *  - F's 46M is a GENESIS delegation (a seeded row — V2X_SEED_NOT_REAL
 *    shape, like KD's), not a DELEGATE transaction; it enters copy(0) and
 *    the genesis snapshots like any genesis bond. F2's tiebreak check
 *    proves the order IS the validator_id order; whether the pubkey
 *    preimage would have ordered these six differently is not asserted
 *    (test_committee_election (7) proves the two arms differ).
 *  - D is a source scan: a NEW reader added inside an already-classified
 *    function is not seen; readers outside the eight scanned files
 *    (nodus_witness_rt_native.c — sub-slice 3c's; handlers.c — 3e /
 *    slice 7; v2_gen.c — genesis) are not inventoried here.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_econ.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_migrate.h"
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_vset.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"
#include "nodus/nodus_types.h"

#include "dnac/dnac.h"
#include "dnac/cmt_pb.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"
#include "dnac/power_cap.h"
#include "dnac/validator.h"
#include "dnac/valbind_wire.h"
#include "dnac/vset_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#ifndef NODUS_HF6_READERS_SRC_DIR
#error "NODUS_HF6_READERS_SRC_DIR must name nodus/src/witness (CMake sets it)"
#endif

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN     ((uint64_t)DNAC_EPOCH_LENGTH)
#define TEN_M     ((uint64_t)DNAC_SELF_STAKE_AMOUNT)
#define TWO_M     ((uint64_t)DNAC_HF6_STAKE_MIN_DEFAULT)
#define EIGHT_M   (TEN_M - TWO_M)
#define MIL       (1000000ULL * 100000000ULL)        /* 1M NODUS raw     */
#define PKLEN     ((size_t)DNAC_PUBKEY_SIZE)
#define VBODY     ((size_t)NODUS_V2_VALIDATOR_LEAF_BODY_LEN)
#define DBODY     ((size_t)NODUS_V2_DELEGATION_LEAF_BODY_LEN)
#define RPOOL     10000000000000000ULL               /* 10^16 raw         */
#define COMM_BPS  500u

#define H9   2u
#define HE   3u
#define H14  4u       /* param 18: the gen-4 edge runs in block H14 − 1 */

static const uint8_t k_found[] = DNAC_HF6_FOUNDATION_OWNER;
_Static_assert(sizeof(k_found) == 64, "64-byte Foundation owner");

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void hex_of(const uint8_t raw[64], char out[129]) {
    static const char hx[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i]     = hx[raw[i] >> 4];
        out[2 * i + 1] = hx[raw[i] & 15];
    }
    out[128] = '\0';
}

static int run_sql(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "SQL failed (%s): %s\n", sql, err ? err : "?");
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int q_u64(nodus_witness_t *w, const char *sql, uint64_t *out) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    sqlite3_int64 v = rc == SQLITE_ROW ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    if (rc != SQLITE_ROW || v < 0) return -1;
    *out = (uint64_t)v;
    return 0;
}

/* ── the test's own RFC 6962 (merkle.c leaf_hash / inner_hash restated) */

static int t_sha3_pre(uint8_t pre, const uint8_t *a, size_t al,
                      const uint8_t *b, size_t bl, uint8_t out[64]) {
    uint8_t *buf = malloc(1 + al + bl);
    if (!buf) return -1;
    buf[0] = pre;
    if (al) memcpy(buf + 1, a, al);
    if (bl) memcpy(buf + 1 + al, b, bl);
    int rc = qgp_sha3_512(buf, 1 + al + bl, out);
    free(buf);
    return rc == 0 ? 0 : -1;
}

/* root over n leaf hashes already prefixed with 0x00 */
static int t_root(const uint8_t (*h)[64], size_t n, uint8_t out[64]) {
    if (n == 1) { memcpy(out, h[0], 64); return 0; }
    size_t k = 1;
    while (k * 2 < n) k *= 2;
    uint8_t l[64], r[64];
    if (t_root(h, k, l) != 0 || t_root(h + k, n - k, r) != 0) return -1;
    return t_sha3_pre(0x01, l, 64, r, 64, out);
}

/* tree over leaf VALUES (SHA3-512(tag ‖ body)), in the given order */
static int t_tree(const uint8_t (*vals)[64], size_t n, uint8_t out[64]) {
    uint8_t (*h)[64] = calloc(n ? n : 1, 64);
    if (!h) return -1;
    int rc = 0;
    for (size_t i = 0; i < n && rc == 0; i++)
        rc = t_sha3_pre(0x00, vals[i], 64, NULL, 0, h[i]);
    if (rc == 0) rc = t_root((const uint8_t (*)[64])h, n, out);
    free(h);
    return rc;
}

/* ══ A. the leaves, on a hand-built migrated DB ════════════════════════ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
    uint8_t          chain32[DNA_CHAIN_ID_LEN];
} fixture_t;

static void fx_close(fixture_t *fx) {
    if (!fx->w) return;
    if (fx->w->db) sqlite3_close(fx->w->db);
    free(fx->w);
    fx->w = NULL;
    char cmd[200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", fx->dir);
    if (system(cmd) != 0) { /* best effort */ }
}

static int fx_dir(fixture_t *fx, const char *tag) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));          /* multi-MB — ALWAYS heap */
    if (!fx->w) return -1;
    fx->w->cached_committee_epoch_start = UINT64_MAX;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf6_readers_%s_XXXXXX",
             tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    return 0;
}

static int fxd_open(fixture_t *fx, const char *tag) {
    if (fx_dir(fx, tag) != 0) return -1;
    memset(fx->chain16, 0x6D, sizeof(fx->chain16));
    return nodus_witness_create_chain_db(fx->w, fx->chain16);
}

static void pk_of(uint8_t fill, uint8_t pk[PKLEN]) { memset(pk, fill, PKLEN); }

static int fp_of(uint8_t fill, uint8_t out[64]) {
    uint8_t pk[PKLEN];
    pk_of(fill, pk);
    return qgp_sha3_512(pk, PKLEN, out) == 0 ? 0 : -1;
}

static int vid_of(const uint8_t chain32[32], uint8_t fill, uint8_t out[64]) {
    uint8_t pk[PKLEN];
    pk_of(fill, pk);
    return dna_validator_id_migrated(out, chain32, pk);
}

static int put_val(nodus_witness_t *w, uint8_t fill, uint8_t status,
                   uint64_t since, uint64_t self, uint64_t deleg) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    pk_of(fill, v.pubkey);
    v.self_stake = self;
    v.total_delegated = deleg;
    v.external_delegated = deleg;
    v.commission_bps = COMM_BPS;
    v.status = status;
    v.active_since_block = since;
    return nodus_validator_insert(w, &v);
}

static int put_del(nodus_witness_t *w, uint8_t dfill, uint8_t vfill,
                   uint64_t amount, uint64_t at) {
    dnac_delegation_record_t d;
    memset(&d, 0, sizeof(d));
    pk_of(dfill, d.delegator_pubkey);
    pk_of(vfill, d.validator_pubkey);
    d.amount = amount;
    d.delegated_at_block = at;
    return nodus_delegation_insert(w, &d);
}

static int migrate_tx(nodus_witness_t *w, uint64_t h_next,
                      const uint8_t chain32[32], const uint8_t found[64]) {
    if (run_sql(w->db, "BEGIN IMMEDIATE") != 0) return 99;
    int rc = nodus_witness_v2_roles_migrate(w, h_next, chain32, found);
    if (run_sql(w->db, rc == 0 ? "COMMIT" : "ROLLBACK") != 0) return 99;
    return rc;
}

/* The §6.3 body, restated from the design's table offset by offset (never
 * through nodus_validator_v2_leaf_encode). No pending key: 2592 × 0x00 and
 * effective epoch 0. */
typedef struct {
    uint8_t  vid[64], owner[64];
    uint8_t  fill;                     /* consensus pubkey = fill bytes  */
    uint64_t self, total, ext;
    uint16_t comm, pcomm;
    uint64_t peb;
    uint8_t  status;
    uint64_t since, ucb, lvub, missed;
} want_val_t;

static void body_of(const want_val_t *x, uint8_t out[5389]) {
    memset(out, 0, 5389);
    memcpy(out + 0, x->vid, 64);
    memcpy(out + 64, x->owner, 64);
    memset(out + 128, x->fill, 2592);
    /* 2720..5311 pending key: zeros; 5312 effective epoch: 0 */
    put64(out + 5312, 0);
    put64(out + 5320, x->self);
    put64(out + 5328, x->total);
    put64(out + 5336, x->ext);
    put16(out + 5344, x->comm);
    put16(out + 5346, x->pcomm);
    put64(out + 5348, x->peb);
    out[5356] = x->status;
    put64(out + 5357, x->since);
    put64(out + 5365, x->ucb);
    put64(out + 5373, x->lvub);
    put64(out + 5381, x->missed);
}

static int t_leaf_bytes(void) {
    fixture_t fx;
    const uint64_t H = 1000;
    uint8_t chain32[32], F[64];
    memset(chain32, 0x5A, sizeof(chain32));
    memset(F, 0xC3, sizeof(F));                      /* a test owner      */

    CHECK(1u + VBODY == 5390u && 1u + DBODY == 145u,
          "§6.3 leaf 5390 bytes, §6.4 leaf 145 bytes");
    CHECK(64u + 64u + 2592u + 2592u + 8u + 8u + 8u + 8u + 2u + 2u + 8u +
              1u + 8u + 8u + 8u + 8u == VBODY &&
          64u + 64u + 8u + 8u == DBODY, "the field widths sum to the bodies");

    CHECK(fxd_open(&fx, "leaf") == 0, "fixture DB");
    nodus_witness_t *w = fx.w;
    CHECK(put_val(w, 0x11, DNAC_VALIDATOR_ACTIVE, 1, TEN_M, 0) == 0 &&
          put_val(w, 0x22, DNAC_VALIDATOR_ELIGIBLE, 500, TEN_M, 3 * MIL)
              == 0 &&
          put_val(w, 0x33, DNAC_VALIDATOR_RETIRING, 1, TEN_M, 0) == 0,
          "three validators");
    CHECK(put_del(w, 0xD1, 0x22, 3 * MIL, 100) == 0, "0xD1 -> 0x22, 3M");
    {
        char sql[256];
        snprintf(sql, sizeof(sql), "UPDATE validators SET "
                 "pending_commission_bps = 700, pending_effective_block = "
                 "5000, last_validator_update_block = 4000, "
                 "consecutive_missed_epochs = 2 WHERE status = %d",
                 (int)DNAC_VALIDATOR_ELIGIBLE);
        CHECK(run_sql(w->db, sql) == 0, "distinct fields on 0x22");
        snprintf(sql, sizeof(sql), "UPDATE validators SET "
                 "unstake_commit_block = 6000 WHERE status = %d",
                 (int)DNAC_VALIDATOR_RETIRING);
        CHECK(run_sql(w->db, sql) == 0, "unstake_commit_block on 0x33");
    }

    /* before the edge there is no roles row: the v2 root FAULTS (v5 is
     * computable only over migrated tables) */
    {
        uint8_t r[64];
        CHECK(nodus_witness_merkle_compute_validator_root_v2(w, r) == -1,
              "pre-migration rows: the validator root v2 faults");
    }

    CHECK(migrate_tx(w, H, chain32, F) == 0, "the migration commits");

    uint8_t fp22[64], fpD1[64], v11[64], v22[64], v33[64];
    CHECK(fp_of(0x22, fp22) == 0 && fp_of(0xD1, fpD1) == 0 &&
          vid_of(chain32, 0x11, v11) == 0 && vid_of(chain32, 0x22, v22) == 0
          && vid_of(chain32, 0x33, v33) == 0, "keys");

    want_val_t wv[3];
    memset(wv, 0, sizeof(wv));
    memcpy(wv[0].vid, v11, 64); memcpy(wv[0].owner, F, 64);
    wv[0].fill = 0x11; wv[0].self = TWO_M; wv[0].total = EIGHT_M;
    wv[0].ext = EIGHT_M; wv[0].comm = COMM_BPS;
    wv[0].status = DNAC_VALIDATOR_ACTIVE; wv[0].since = 1;
    memcpy(wv[1].vid, v22, 64); memcpy(wv[1].owner, fp22, 64);
    wv[1].fill = 0x22; wv[1].self = TWO_M; wv[1].total = 3 * MIL + EIGHT_M;
    wv[1].ext = 3 * MIL + EIGHT_M; wv[1].comm = COMM_BPS; wv[1].pcomm = 700;
    wv[1].peb = 5000; wv[1].status = DNAC_VALIDATOR_ELIGIBLE;
    wv[1].since = 500; wv[1].lvub = 4000; wv[1].missed = 2;
    memcpy(wv[2].vid, v33, 64); memcpy(wv[2].owner, F, 64);
    wv[2].fill = 0x33; wv[2].self = TEN_M; wv[2].comm = COMM_BPS;
    wv[2].status = DNAC_VALIDATOR_RETIRING; wv[2].since = 1;
    wv[2].ucb = 6000;

    uint8_t vals[3][64];
    {
        uint8_t *want = malloc(5389), *got = malloc(5389);
        nodus_v2_validator_row_t *row = calloc(1, sizeof(*row));
        CHECK(want && got && row, "alloc");
        int ok = 1;
        for (int i = 0; i < 3 && ok; i++) {
            body_of(&wv[i], want);
            ok = nodus_validator_v2_get(w, wv[i].vid, row) == 0 &&
                 nodus_validator_v2_leaf_encode(row, got) == 0 &&
                 memcmp(want, got, 5389) == 0 &&
                 t_sha3_pre(NODUS_TREE_TAG_VALIDATOR, want, 5389, NULL, 0,
                            vals[i]) == 0;
        }
        free(want); free(got); free(row);
        CHECK(ok, "each migrated row encodes to the §6.3 table, byte for "
              "byte");
    }
    {
        uint8_t ord[3][64], idx_vid[3][64];
        /* leaf order = validator_id ASC: sort (vid, value) pairs by vid */
        for (int i = 0; i < 3; i++) memcpy(idx_vid[i], wv[i].vid, 64);
        int perm[3] = { 0, 1, 2 };
        for (int a = 1; a < 3; a++)
            for (int b = a; b > 0 &&
                 memcmp(idx_vid[perm[b]], idx_vid[perm[b - 1]], 64) < 0; b--) {
                int t = perm[b]; perm[b] = perm[b - 1]; perm[b - 1] = t;
            }
        for (int i = 0; i < 3; i++) memcpy(ord[i], vals[perm[i]], 64);
        uint8_t want_root[64], got_root[64];
        CHECK(t_tree((const uint8_t (*)[64])ord, 3, want_root) == 0 &&
              nodus_witness_merkle_compute_validator_root_v2(w, got_root)
                  == 0 && memcmp(want_root, got_root, 64) == 0,
              "validator root v2 == the hand-built RFC 6962 root");

        /* a missing roles row, then an orphan roles row: both FAULT */
        CHECK(run_sql(w->db, "CREATE TEMP TABLE keep AS SELECT * FROM "
                      "v2_validator_roles") == 0, "stash");
        sqlite3_stmt *st = NULL;
        CHECK(sqlite3_prepare_v2(w->db, "DELETE FROM v2_validator_roles "
                                 "WHERE validator_id = ?1", -1, &st, NULL)
              == SQLITE_OK, "prepare");
        sqlite3_bind_blob(st, 1, v22, 64, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_finalize(st);
        CHECK(rc == SQLITE_DONE, "one roles row deleted");
        CHECK(nodus_witness_merkle_compute_validator_root_v2(w, got_root)
                  == -1, "a validators row without its roles row: FAULT");
        CHECK(run_sql(w->db, "INSERT INTO v2_validator_roles SELECT * FROM "
                      "keep WHERE validator_id NOT IN (SELECT validator_id "
                      "FROM v2_validator_roles)") == 0, "restored");
        CHECK(nodus_witness_merkle_compute_validator_root_v2(w, got_root)
                  == 0 && memcmp(want_root, got_root, 64) == 0,
              "restored: the same root");
        CHECK(run_sql(w->db, "INSERT INTO v2_validator_roles (validator_id, "
                      "owner_fp, pending_consensus_pubkey, "
                      "consensus_key_effective_epoch) VALUES (zeroblob(64), "
                      "zeroblob(64), zeroblob(2592), 0)")
              == 0, "an orphan roles row");
        CHECK(nodus_witness_merkle_compute_validator_root_v2(w, got_root)
                  == -1, "an orphan roles row: FAULT");
        CHECK(run_sql(w->db, "DELETE FROM v2_validator_roles WHERE "
                      "validator_id = zeroblob(64)") == 0, "orphan removed");
        CHECK(nodus_witness_merkle_compute_validator_root_v2(w, got_root)
                  == 0 && memcmp(want_root, got_root, 64) == 0,
              "and the root is back");
    }

    /* §6.4: (fpD1, v22, 3M, 100), (fp22, v22, 8M, H), (F, v11, 8M, H) */
    {
        struct { uint8_t dfp[64], vid[64]; uint64_t amt, at; } wd[3];
        memcpy(wd[0].dfp, fpD1, 64); memcpy(wd[0].vid, v22, 64);
        wd[0].amt = 3 * MIL; wd[0].at = 100;
        memcpy(wd[1].dfp, fp22, 64); memcpy(wd[1].vid, v22, 64);
        wd[1].amt = EIGHT_M; wd[1].at = H;
        memcpy(wd[2].dfp, F, 64); memcpy(wd[2].vid, v11, 64);
        wd[2].amt = EIGHT_M; wd[2].at = H;
        uint8_t keys[3][128], dvals[3][64];
        for (int i = 0; i < 3; i++) {
            memcpy(keys[i], wd[i].vid, 64);
            memcpy(keys[i] + 64, wd[i].dfp, 64);
        }
        int perm[3] = { 0, 1, 2 };
        for (int a = 1; a < 3; a++)
            for (int b = a; b > 0 &&
                 memcmp(keys[perm[b]], keys[perm[b - 1]], 128) < 0; b--) {
                int t = perm[b]; perm[b] = perm[b - 1]; perm[b - 1] = t;
            }
        int ok = 1;
        for (int i = 0; i < 3 && ok; i++) {
            const int k = perm[i];
            uint8_t body[144], enc[144];
            memcpy(body, wd[k].dfp, 64);
            memcpy(body + 64, wd[k].vid, 64);
            put64(body + 128, wd[k].amt);
            put64(body + 136, wd[k].at);
            nodus_v2_delegation_row_t d;
            ok = nodus_delegation_v2_get(w, wd[k].dfp, wd[k].vid, &d) == 0 &&
                 nodus_delegation_v2_leaf_encode(&d, enc) == 0 &&
                 memcmp(enc, body, 144) == 0 &&
                 t_sha3_pre(NODUS_TREE_TAG_DELEGATION, body, 144, NULL, 0,
                            dvals[i]) == 0;
        }
        CHECK(ok, "each delegation encodes to the §6.4 layout");
        uint64_t n = 0;
        CHECK(q_u64(w, "SELECT COUNT(*) FROM delegations", &n) == 0 && n == 3,
              "exactly three delegation rows");
        uint8_t want_root[64], got_root[64];
        CHECK(t_tree((const uint8_t (*)[64])dvals, 3, want_root) == 0 &&
              nodus_witness_merkle_compute_delegation_root_v2(w, got_root)
                  == 0 && memcmp(want_root, got_root, 64) == 0,
              "delegation root v2 == the hand-built RFC 6962 root");
    }
    fx_close(&fx);

    /* the empty tables: the tagged sentinels */
    {
        uint8_t a[64], b[64];
        CHECK(fxd_open(&fx, "empty") == 0, "empty DB");
        CHECK(nodus_witness_merkle_compute_validator_root_v2(fx.w, a) == 0 &&
              nodus_merkle_empty_root(NODUS_TREE_TAG_VALIDATOR, b) == 0 &&
              memcmp(a, b, 64) == 0, "empty validators: the 0x02 sentinel");
        CHECK(nodus_witness_merkle_compute_delegation_root_v2(fx.w, a) == 0 &&
              nodus_merkle_empty_root(NODUS_TREE_TAG_DELEGATION, b) == 0 &&
              memcmp(a, b, 64) == 0, "empty delegations: the 0x03 sentinel");
        fx_close(&fx);
    }
    return 0;
}

/* ══ B / C. the engine ════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t fp[64];
    char    hex[129];
} key_t_;

/* V0..V6 the committee; VR the RETIRING row; KD delegates to V0; KR to VR;
 * KB the large genesis delegation to V0 of case F (HF-6 5d) */
enum { V0, V1, V2, V3, V4, V5, V6, VR, KD, KR, KB, N_KEYS };
#define N_VAL 7
static key_t_ g_k[N_KEYS];
static uint8_t g_vaddr[N_VAL][32];
static int32_t g_vflag[N_VAL];

static int keys_make(void) {
    for (int i = 0; i < N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, 0x61 + i, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_k[i].pk, g_k[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_k[i].pk, PKLEN, g_k[i].fp) != 0) return -1;
        hex_of(g_k[i].fp, g_k[i].hex);
    }
    for (int i = 0; i < N_VAL; i++) {
        if (nodus_chain_config_derive_witness_id(g_k[i].pk, g_vaddr[i]) != 0)
            return -1;
        g_vflag[i] = (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT;
    }
    return 0;
}

static int cc_row(nodus_witness_t *w, unsigned param, uint64_t value,
                  uint64_t effective, uint64_t nonce) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "INSERT INTO chain_config_history (param_id, new_value, "
            "effective_block, commit_block, tx_hash, proposal_nonce, "
            "created_at_unix) VALUES (?1, ?2, ?3, 0, zeroblob(64), ?4, 0)",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)param);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)value);
    sqlite3_bind_int64(st, 3, (sqlite3_int64)effective);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)nonce);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    w->chain_config_cache_warm = false;
    return rc == SQLITE_DONE ? 0 : -1;
}

static int seed_val(nodus_witness_t *w, int k, uint8_t status,
                    uint64_t since, uint64_t deleg) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_k[k].pk, PKLEN);
    v.self_stake = TEN_M;
    v.total_delegated = deleg;
    v.external_delegated = deleg;
    v.commission_bps = COMM_BPS;
    v.status = status;
    v.active_since_block = since;
    memcpy(v.unstake_destination_fp, g_k[k].hex, 129);
    return nodus_validator_insert(w, &v);
}

static int seed_del(nodus_witness_t *w, int dk, int vk, uint64_t amount) {
    dnac_delegation_record_t d;
    memset(&d, 0, sizeof(d));
    memcpy(d.delegator_pubkey, g_k[dk].pk, PKLEN);
    memcpy(d.validator_pubkey, g_k[vk].pk, PKLEN);
    d.amount = amount;
    d.delegated_at_block = 1;
    return nodus_delegation_insert(w, &d);
}

#define KD_AMT  (4 * MIL)
#define KR_AMT  (3 * MIL)

/* A seeded chain: param 9 at H9, param 14 at HE, param 18 at H14 (the
 * gen-4 edge in block H14 − 1); V0..V6 ACTIVE 10M (V6 active_since
 * `v6_since`, the rest 1); KD → V0 4M; with `retiring`, VR RETIRING 10M
 * since 1 with KR → VR 3M; with `kb_amt` > 0 (case F) also KB → V0
 * `kb_amt` at genesis; reward pool RPOOL. */
static int fx_open(fixture_t *fx, const char *tag, uint64_t v6_since,
                   int retiring, uint64_t kb_amt) {
    if (fx_dir(fx, tag) != 0) return -1;
    memset(fx->chain16, 0x6E, sizeof(fx->chain16));
    nodus_witness_t *w = fx->w;
    if (v2x_seed_prepare(w, fx->chain16, 0) != 0) return -1;
    if (cc_row(w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN2, (uint64_t)DNAC_CFG_RULESET_GEN2_D2,
               H9, 12) != 0 ||
        cc_row(w, DNAC_CFG_EVM_ACTIVE, (uint64_t)DNAC_CFG_EVM_ACTIVE_D, HE,
               14) != 0 ||
        cc_row(w, DNAC_CFG_RULESET_GEN_ROLES,
               (uint64_t)DNAC_CFG_RULESET_GEN_ROLES_D, H14, 13) != 0)
        return -1;
    uint64_t bonds = 0, deleg = 0;
    for (int i = 0; i < N_VAL; i++) {
        if (seed_val(w, i, (uint8_t)DNAC_VALIDATOR_ACTIVE,
                     i == V6 ? v6_since : 1,
                     i == V0 ? KD_AMT + kb_amt : 0) != 0)
            return -1;
        bonds += TEN_M;
    }
    if (seed_del(w, KD, V0, KD_AMT) != 0) return -1;
    deleg += KD_AMT;
    if (kb_amt > 0) {
        if (seed_del(w, KB, V0, kb_amt) != 0) return -1;
        deleg += kb_amt;
    }
    if (retiring) {
        if (seed_val(w, VR, (uint8_t)DNAC_VALIDATOR_RETIRING, 1, KR_AMT)
                != 0 ||
            seed_del(w, KR, VR, KR_AMT) != 0)
            return -1;
        bonds += TEN_M;
        deleg += KR_AMT;
    }
    {
        /* not a real genesis: a non-zero reward pool (the test_v2_econ
         * device) so every boundary distributes */
        const uint64_t supply = bonds + deleg + RPOOL;
        char sql[400];
        snprintf(sql, sizeof(sql),
                 "INSERT INTO supply_tracking (id, genesis_supply, "
                 "total_burned, total_minted, current_supply, "
                 "last_tx_hash, last_sequence, reward_pool) VALUES (1, "
                 "%llu, 0, 0, %llu, zeroblob(64), 0, %llu)",
                 (unsigned long long)supply, (unsigned long long)supply,
                 (unsigned long long)RPOOL);
        if (v2x_sql(w->db, sql) != 0) return -1;
    }
    if (retiring) v2x_seed_not_real(V2X_SEED_NOT_REAL_STATUSES);
    if (v2x_seed_genesis(w, fx->chain16, 0, NULL, 0, fx->chain32) != 0)
        return -1;
    return 0;
}

static void mk_block(nodus_v2_block_t *b, uint64_t h) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    if (h > 1) {
        b->cmt.votes_address = (const uint8_t (*)[32])g_vaddr;
        b->cmt.votes_block_id_flag = g_vflag;
        b->cmt.votes_len = N_VAL;
    }
}

static int head_root(nodus_witness_t *w, uint32_t dom, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT head FROM v2_domain_heads WHERE "
                           "domain_id = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        memcpy(out, (const uint8_t *)sqlite3_column_blob(st, 0) + 4, 64);
        ok = 0;
    }
    sqlite3_finalize(st);
    return ok;
}

/* the committed SYSTEM head == its runtime's recomputation */
static int sys_head_recomputes(nodus_witness_t *w) {
    uint8_t committed[64], now[64];
    const nodus_domain_runtime_t *rt = NULL;
    if (head_root(w, DNA_DOMAIN_SYSTEM, committed) != 0 ||
        nodus_witness_v2_runtime_for(w, DNA_DOMAIN_SYSTEM, 1, &rt) != 0 ||
        !rt || !rt->state_root || rt->state_root(rt, w, now) != 0)
        return -1;
    return memcmp(committed, now, 64) == 0 ? 0 : -1;
}

static int apply_one(fixture_t *fx, uint64_t h) {
    nodus_v2_block_t b;
    mk_block(&b, h);
    if (v2x_cmt_apply(fx->w, &b) != 0) {
        fprintf(stderr, "block %llu refused: %s\n", (unsigned long long)h,
                b.out_reason);
        return -1;
    }
    if ((h % E_LEN) == 0 && sys_head_recomputes(fx->w) != 0) {
        fprintf(stderr, "block %llu: SYSTEM head does not recompute\n",
                (unsigned long long)h);
        return -1;
    }
    return 0;
}

/* twins: both apply, the committed global roots agree */
static int apply_both(fixture_t *a, fixture_t *b, uint64_t h) {
    if (apply_one(a, h) != 0) return -1;
    if (b) {
        uint8_t ca[64], cb[64];
        if (apply_one(b, h) != 0 ||
            nodus_witness_v2_committed_global_root(a->w, ca) != 0 ||
            nodus_witness_v2_committed_global_root(b->w, cb) != 0 ||
            memcmp(ca, cb, 64) != 0) {
            fprintf(stderr, "block %llu: twin global roots differ\n",
                    (unsigned long long)h);
            return -1;
        }
    }
    return 0;
}

static int run_to(fixture_t *a, fixture_t *b, uint64_t *h, uint64_t last) {
    while (*h < last) {
        if (apply_both(a, b, *h + 1) != 0) return -1;
        (*h)++;
    }
    return 0;
}

static int accrual_of(nodus_witness_t *w, const uint8_t fp[64],
                      uint64_t *out, int *present) {
    sqlite3_stmt *st = NULL;
    *out = 0;
    if (present) *present = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT amount FROM v2_reward_accrual "
                           "WHERE owner_fp = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, fp, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        *out = (uint64_t)sqlite3_column_int64(st, 0);
        if (present) *present = 1;
    }
    sqlite3_finalize(st);
    return (rc == SQLITE_ROW || rc == SQLITE_DONE) ? 0 : -1;
}

static int utxo_sum(nodus_witness_t *w, const char hex[129], uint64_t *out) {
    sqlite3_stmt *st = NULL;
    *out = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT COALESCE(SUM(amount), 0) FROM "
                           "utxo_set WHERE owner = ?1", -1, &st, NULL)
        != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, hex, 128, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *out = (uint64_t)sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

static uint64_t muldiv(uint64_t a, uint64_t b, uint64_t d) {
    return (uint64_t)(((unsigned __int128)a * b) / d);
}

/* The distribution at boundary B, restated (design §7.1 split, §1.6 owner,
 * §7.5 bridge): who is owed what, read BEFORE block B is applied. */
#define OWED_MAX 32
typedef struct {
    uint8_t  fp[OWED_MAX][64];
    uint64_t amt[OWED_MAX];
    uint64_t before[OWED_MAX];
    size_t   n;
    uint64_t total;
    uint64_t pool;
    /* observations of the governing snapshot / copy */
    uint16_t members;
    uint64_t self_bond_min, self_bond_max;
    int      found_8m_rows;     /* kind-1 rows of exactly 8M owned by the
                                 * member's owner (the self-delegation) */
    int      v6_member;
} owed_t;

static int owed_add(owed_t *o, const uint8_t fp[64], uint64_t x) {
    for (size_t i = 0; i < o->n; i++)
        if (memcmp(o->fp[i], fp, 64) == 0) { o->amt[i] += x; o->total += x;
                                             return 0; }
    if (o->n == OWED_MAX) return -1;
    memcpy(o->fp[o->n], fp, 64);
    o->amt[o->n] = x;
    o->n++;
    o->total += x;
    return 0;
}

static int expect_dist(nodus_witness_t *w, uint64_t B,
                       const uint8_t chain32[32], owed_t *o) {
    memset(o, 0, sizeof(*o));
    o->self_bond_min = UINT64_MAX;
    if (q_u64(w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
              &o->pool) != 0)
        return -1;
    const uint64_t payout = o->pool >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2;
    const uint64_t src = B >= 3 * E_LEN ? B - 3 * E_LEN : 0;
    dna_vset_snapshot_t *snap = NULL;
    if (nodus_witness_v2_epoch_authority_for_epoch(w, B - E_LEN, &snap, NULL,
                                                   NULL) != 0 || !snap)
        return -1;
    int ret = -1;
    nodus_v2_validator_row_t *row = calloc(1, sizeof(*row));
    uint64_t sum_power = 0;
    if (!row) goto out;
    o->members = snap->active_count;
    for (uint16_t i = 0; i < snap->active_count; i++)
        sum_power += snap->entries[i].total_stake / DNAC_DECIMAL_UNIT;
    for (uint16_t i = 0; i < snap->active_count; i++) {
        const dna_vset_entry_t *e = &snap->entries[i];
        if (e->self_bond < o->self_bond_min) o->self_bond_min = e->self_bond;
        if (e->self_bond > o->self_bond_max) o->self_bond_max = e->self_bond;
        if (memcmp(e->pubkey, g_k[V6].pk, PKLEN) == 0) o->v6_member = 1;
        uint8_t vid[64];
        /* the row the migrated id names holds this entry's pubkey */
        if (dna_validator_id_migrated(vid, chain32, e->pubkey) != 0 ||
            nodus_validator_v2_get(w, vid, row) != 0 ||
            memcmp(row->rec.pubkey, e->pubkey, PKLEN) != 0)
            goto out;
        const uint64_t power = e->total_stake / DNAC_DECIMAL_UNIT;
        const uint64_t share = sum_power ? muldiv(payout, power, sum_power)
                                         : 0;
        if (share == 0) continue;
        const uint64_t base = muldiv(share, e->self_bond, e->total_stake);
        const uint64_t gross = share - base;
        const uint64_t comm = muldiv(gross, e->commission_bps, 10000);
        const uint64_t net = gross - comm;
        if (owed_add(o, row->owner_fp, base + comm) != 0) goto out;

        /* the member's kind-1 copy(src) rows, (owner_fp, kind) ASC */
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db, "SELECT owner_fp, amount FROM "
                               "v2_balance_copy WHERE epoch_start = ?1 AND "
                               "validator_fp = ?2 AND kind = 1 ORDER BY "
                               "owner_fp ASC", -1, &st, NULL) != SQLITE_OK)
            goto out;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)src);
        sqlite3_bind_blob(st, 2, vid, 64, SQLITE_TRANSIENT);
        uint8_t dfp[8][64];
        uint64_t a[8], sum_d = 0;
        int nd = 0, rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW && nd < 8) {
            if (sqlite3_column_bytes(st, 0) != 64) break;
            memcpy(dfp[nd], sqlite3_column_blob(st, 0), 64);
            a[nd] = (uint64_t)sqlite3_column_int64(st, 1);
            sum_d += a[nd];
            if (a[nd] == EIGHT_M && memcmp(dfp[nd], row->owner_fp, 64) == 0)
                o->found_8m_rows++;
            nd++;
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto out;
        if (sum_d != e->total_stake - e->self_bond) goto out;   /* gate */
        if (net > 0 && sum_d > 0)
            for (int d = 0; d < nd; d++)
                if (owed_add(o, dfp[d], muldiv(net, a[d], sum_d)) != 0)
                    goto out;
    }
    for (size_t i = 0; i < o->n; i++)
        if (accrual_of(w, o->fp[i], &o->before[i], NULL) != 0) goto out;
    ret = 0;
out:
    free(row);
    dna_vset_free(&snap);
    return ret;
}

/* after block B: every owed fp moved by exactly its amount, the pool by Σ */
static int owed_check(nodus_witness_t *w, const owed_t *o) {
    for (size_t i = 0; i < o->n; i++) {
        uint64_t now = 0;
        if (accrual_of(w, o->fp[i], &now, NULL) != 0) return -1;
        if (now - o->before[i] != o->amt[i]) {
            fprintf(stderr, "owed row %zu: delta %llu, expected %llu\n", i,
                    (unsigned long long)(now - o->before[i]),
                    (unsigned long long)o->amt[i]);
            return -1;
        }
    }
    uint64_t pool = 0;
    if (q_u64(w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
              &pool) != 0 || o->pool - pool != o->total) {
        fprintf(stderr, "pool debit %llu, expected %llu\n",
                (unsigned long long)(o->pool - pool),
                (unsigned long long)o->total);
        return -1;
    }
    return 0;
}

static int owed_of(const owed_t *o, const uint8_t fp[64], uint64_t *amt) {
    for (size_t i = 0; i < o->n; i++)
        if (memcmp(o->fp[i], fp, 64) == 0) { *amt = o->amt[i]; return 0; }
    *amt = 0;
    return 1;
}

/* snapshot(e) holds exactly V0..V6 (any order); its self_bond / total */
static int snap_is_seven(nodus_witness_t *w, uint64_t e, uint64_t want_self,
                         uint64_t want_total) {
    dna_vset_snapshot_t *s = NULL;
    if (nodus_witness_v2_epoch_authority_for_epoch(w, e, &s, NULL, NULL) != 0
        || !s)
        return -1;
    int ok = s->active_count == N_VAL;
    for (int k = 0; k < N_VAL && ok; k++) {
        int hit = 0;
        for (uint16_t i = 0; i < s->active_count; i++)
            if (memcmp(s->entries[i].pubkey, g_k[k].pk, PKLEN) == 0) {
                hit = 1;
                if (s->entries[i].self_bond != want_self ||
                    s->entries[i].total_stake !=
                        want_total + (k == V0 ? KD_AMT : 0))
                    ok = 0;
            }
        if (!hit) ok = 0;
    }
    dna_vset_free(&s);
    return ok ? 0 : -1;
}

static int t_engine_foundation(void) {
    fixture_t A, B;
    uint64_t h = 0, iv = 0;
    CHECK(E_LEN >= 8, "no epoch boundary among heights 1..H14");
    CHECK(keys_make() == 0, "keys");
    CHECK(fx_open(&A, "fa", 1, 1, 0) == 0 && fx_open(&B, "fb", 1, 1, 0) == 0,
          "twin seeded chains (gen-4 edge in block H14-1)");
    CHECK(nodus_witness_v2_payout_interval(A.w, &iv) == 0 && iv >= 5,
          "no payday inside 1..4E");

    CHECK(run_to(&A, &B, &h, H14 - 1) == 0, "blocks 1..H14-1 (the edge)");
    {
        const nodus_domain_runtime_t *rs = NULL;
        uint64_t n = 0;
        CHECK(nodus_witness_v2_runtime_for(A.w, DNA_DOMAIN_SYSTEM, 1, &rs)
                  == 0 && rs && rs->generation == NODUS_RT_GEN_STORAGE,
              "generation 4 after H14-1");
        CHECK(q_u64(A.w, "SELECT COUNT(*) FROM v2_validator_roles", &n) == 0
              && n == N_VAL + 1, "eight roles rows (seven + VR)");
        CHECK(sys_head_recomputes(A.w) == 0 && sys_head_recomputes(B.w) == 0,
              "the H-1 SYSTEM head is v5 over the v2 leaves");
    }
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");

    uint8_t vid_r[64];
    uint64_t r_self = 0, r_deleg = 0;
    {
        nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
        CHECK(r && dna_validator_id_migrated(vid_r, chain32, g_k[VR].pk) == 0
              && nodus_validator_v2_get(A.w, vid_r, r) == 0 &&
              r->rec.status == DNAC_VALIDATOR_RETIRING &&
              memcmp(r->owner_fp, k_found, 64) == 0, "VR: RETIRING, "
              "Foundation-owned");
        r_self = r->rec.self_stake;
        r_deleg = r->rec.total_delegated;
        free(r);
        CHECK(r_self == TEN_M && r_deleg == KR_AMT,
              "VR's amounts untouched by the migration");
    }

    for (uint64_t k = 1; k <= 4; k++) {
        const uint64_t Bh = k * E_LEN;
        owed_t o;
        CHECK(run_to(&A, &B, &h, Bh - 1) == 0, "idle to B-1");
        CHECK(expect_dist(A.w, Bh, chain32, &o) == 0,
              "the restated split (gate holds on the test side)");
        CHECK(o.members == N_VAL && o.total > 0, "seven paid members");
        if (k <= 3)
            CHECK(o.self_bond_min == TEN_M && o.self_bond_max == TEN_M,
                  "E..3E: governed by the PRE-H copy(0) — self_bond 10M");
        else
            CHECK(o.self_bond_min == TWO_M && o.self_bond_max == TWO_M &&
                  o.found_8m_rows == N_VAL,
                  "4E: the POST-H copy(E) — self_bond 2M, an 8M "
                  "Foundation-owned self-delegation per member");
        CHECK(run_to(&A, &B, &h, Bh) == 0,
              "the boundary applies on both twins (no FAULT)");
        CHECK(owed_check(A.w, &o) == 0 && owed_check(B.w, &o) == 0,
              "every accrual moved by exactly the restated amount");
        {
            uint64_t fa = 0, kd = 0;
            CHECK(owed_of(&o, k_found, &fa) == 0 && fa > 0,
                  "base + commission (+ the 8M share) to the Foundation "
                  "owner");
            CHECK(owed_of(&o, g_k[KD].fp, &kd) == 0 && kd > 0,
                  "KD's delegation share to KD");
            CHECK(o.n == 2, "nobody else is owed anything");
        }
        for (int i = 0; i < N_VAL; i++) {
            uint64_t a = 0;
            int present = 1;
            CHECK(accrual_of(A.w, g_k[i].fp, &a, &present) == 0 &&
                  !present, "no node-key accrual row is reborn (§7.5)");
        }
        if (k == 1) {
            char hexF[129];
            uint64_t uf = 0, ur = 0, n = 0;
            nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
            hex_of(k_found, hexF);
            CHECK(r && nodus_validator_v2_get(A.w, vid_r, r) == 0 &&
                  r->rec.status == DNAC_VALIDATOR_UNSTAKED &&
                  r->rec.self_stake == 0 && r->rec.total_delegated == 0 &&
                  r->rec.external_delegated == 0,
                  "VR graduated at E: UNSTAKED, amounts zero");
            free(r);
            CHECK(utxo_sum(A.w, hexF, &uf) == 0 && uf == r_self,
                  "the 10M bond is a UTXO owned by the Foundation owner");
            CHECK(utxo_sum(A.w, g_k[KR].hex, &ur) == 0 && ur == r_deleg,
                  "KR's 3M is a UTXO owned by KR's fp");
            CHECK(uf + ur == r_self + r_deleg, "released totals equal");
            {
                sqlite3_stmt *st = NULL;
                CHECK(sqlite3_prepare_v2(A.w->db, "SELECT COUNT(*) FROM "
                                         "delegations WHERE validator_hash "
                                         "= ?1", -1, &st, NULL) == SQLITE_OK,
                      "prepare");
                sqlite3_bind_blob(st, 1, vid_r, 64, SQLITE_TRANSIENT);
                int rc = sqlite3_step(st);
                n = rc == SQLITE_ROW ? (uint64_t)sqlite3_column_int64(st, 0)
                                     : 99;
                sqlite3_finalize(st);
                CHECK(n == 0, "no delegation names VR any more");
            }
        }
        CHECK(snap_is_seven(A.w, Bh + E_LEN,
                            k == 1 ? TEN_M : TWO_M,
                            k == 1 ? TEN_M : TWO_M + EIGHT_M) == 0,
              "the gen-4 committee re-selects the same seven");
    }
    {
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(B.w, db) == 0 &&
              memcmp(da, db, 64) == 0, "twin databases byte-identical");
    }
    fx_close(&A);
    fx_close(&B);
    return 0;
}

static int t_engine_own_owner(void) {
    fixture_t O;
    uint64_t h = 0;
    CHECK(keys_make() == 0, "keys");
    CHECK(fx_open(&O, "own", 2, 0, 0) == 0, "seeded chain, V6 since 2");
    CHECK(run_to(&O, NULL, &h, H14 - 1) == 0, "blocks 1..H14-1");
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    CHECK(nodus_witness_v2_chain_id(O.w, chain32) == 0, "chain id");
    {
        nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
        uint8_t vid[64];
        CHECK(r && dna_validator_id_migrated(vid, chain32, g_k[V6].pk) == 0 &&
              nodus_validator_v2_get(O.w, vid, r) == 0 &&
              memcmp(r->owner_fp, g_k[V6].fp, 64) == 0,
              "V6 (since 2): owner = SHA3-512(its pubkey) (D2)");
        CHECK(dna_validator_id_migrated(vid, chain32, g_k[V0].pk) == 0 &&
              nodus_validator_v2_get(O.w, vid, r) == 0 &&
              memcmp(r->owner_fp, k_found, 64) == 0,
              "V0 (since 1): the Foundation owner");
        free(r);
    }
    for (uint64_t k = 1; k <= 4; k++) {
        const uint64_t Bh = k * E_LEN;
        owed_t o;
        CHECK(run_to(&O, NULL, &h, Bh - 1) == 0, "idle to B-1");
        CHECK(expect_dist(O.w, Bh, chain32, &o) == 0, "restated split");
        CHECK(run_to(&O, NULL, &h, Bh) == 0, "the boundary applies");
        CHECK(owed_check(O.w, &o) == 0, "every accrual moved exactly");
        uint64_t v6 = 0;
        int owed6 = owed_of(&o, g_k[V6].fp, &v6) == 0 && v6 > 0;
        CHECK(owed6 == o.v6_member, "V6 is paid at its own fp exactly when "
              "it is a member of the governing snapshot");
        if (k == 1)
            CHECK(o.v6_member && owed6, "E: V6's base to its own fp");
        if (k == 4)
            CHECK(o.v6_member && o.self_bond_min == TWO_M &&
                  o.found_8m_rows == o.members,
                  "4E: V6 seated from copy(E) — its 2M base and its own 8M "
                  "self-delegation share both land on its own fp");
        for (int i = 0; i < V6; i++) {
            uint64_t a = 0;
            int present = 1;
            CHECK(accrual_of(O.w, g_k[i].fp, &a, &present) == 0 && !present,
                  "no Foundation-owned node key accrues");
        }
    }
    fx_close(&O);
    return 0;
}

/* ══ E. HF-6 slice 5c — a RULESET-2 governing snapshot, by validator_id ═
 *
 * See the file header, case E. Helpers first. */

/* Overwrite the stored row of snap->epoch with `s` (any ruleset), test-
 * only: nodus_witness_vset_insert would CONFLICT (-2) on a differing hash
 * for an existing row, by design — the same bypass test_cmt_app.c's
 * t_val_updates_boundary_diff makes. */
static int snap_overwrite(nodus_witness_t *w, const dna_vset_snapshot_t *s) {
    size_t need = dna_vset_encoded_len_ex(s, DNA_VSET_RULESET_TOPN_V2);
    if (need == 0) return -1;
    uint8_t *b = malloc(need);
    uint8_t h[64];
    int ok = -1;
    sqlite3_stmt *st = NULL;
    if (!b) return -1;
    if (dna_vset_encode_ex(s, DNA_VSET_RULESET_TOPN_V2, b, need, NULL) != 0 ||
        dna_vset_hash_bytes_ex(b, need, DNA_VSET_RULESET_TOPN_V2, h) != 0)
        goto out;
    if (sqlite3_prepare_v2(w->db, "UPDATE validator_set_snapshots SET "
                           "active_count = ?1, snapshot_hash = ?2, "
                           "snapshot_blob = ?3 WHERE epoch_start = ?4", -1,
                           &st, NULL) != SQLITE_OK)
        goto out;
    sqlite3_bind_int(st, 1, (int)s->active_count);
    sqlite3_bind_blob(st, 2, h, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, b, (int)need, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 4, (sqlite3_int64)s->epoch);
    if (sqlite3_step(st) == SQLITE_DONE && sqlite3_changes(w->db) == 1)
        ok = 0;
out:
    if (st) sqlite3_finalize(st);
    free(b);
    return ok;
}

/* HF-6 5d: the STORED snapshot(e), which the engine built at a
 * generation-4 boundary — so it must be RULESET 2, and every entry's
 * validator_id must be the migrated id of its pubkey (every row of
 * fixture B is a migrated row) and its owner_fp that row's. A decoded
 * copy the caller may mutate; NULL on any failure or mismatch. */
static dna_vset_snapshot_t *stored_v2(nodus_witness_t *w, uint64_t e,
                                      const uint8_t chain32[32]) {
    dna_vset_snapshot_t *s = NULL;
    nodus_v2_validator_row_t *row = calloc(1, sizeof(*row));
    if (!row) return NULL;
    if (nodus_witness_vset_get(w, e, &s, NULL) != 0 || !s ||
        s->selection_ruleset != DNA_VSET_RULESET_TOPN_V2)
        goto fail;
    for (uint16_t i = 0; i < s->active_count; i++) {
        uint8_t vid[64];
        if (dna_validator_id_migrated(vid, chain32, s->entries[i].pubkey)
                != 0 ||
            nodus_validator_v2_get(w, vid, row) != 0 ||
            memcmp(s->entries[i].validator_id, vid, 64) != 0 ||
            memcmp(s->entries[i].owner_fp, row->owner_fp, 64) != 0)
            goto fail;
    }
    free(row);
    return s;
fail:
    free(row);
    dna_vset_free(&s);
    return NULL;
}

/* The ruleset-1 shape of a snapshot: the same entries in the same order,
 * ids zeroed (the v1 layout has no slot for them). In place. */
static void to_v1(dna_vset_snapshot_t *s) {
    for (uint16_t i = 0; i < s->active_count; i++) {
        memset(s->entries[i].validator_id, 0, 64);
        memset(s->entries[i].owner_fp, 0, 64);
    }
    s->selection_ruleset = DNA_VSET_RULESET_TOPN_V1;
}

/* The distribution at boundary B over the GIVEN snapshot (what the engine
 * will read as snapshot(B − E)), restated per design §5 "Ödül" (K2: share
 * by the counted power over Σcounted; the inner split on the raw entry
 * amounts), §1.6 and §7.5:
 *   power  ruleset 1: total / 10^8; ruleset 2: dna_power_cap_counted at
 *          the compiled ratio over (total / 10^8, entry.validator_id) —
 *          the shared/dnac oracle-pinned function, NOT the witness helper;
 *   row    ruleset 2: keyed by entry.validator_id; ruleset 1: by the
 *          migrated id of entry.pubkey (nodus_validator_v2_get — never by
 *          pubkey); no row ⇒ unpaid;
 *   payee  ruleset 2: entry.owner_fp; ruleset 1: the row's owner_fp.
 * Every member is assumed to meet the attendance bar (all seven sign
 * every block); `counted_out` (n entries) receives the powers used. */
static int expect_snap(nodus_witness_t *w, const dna_vset_snapshot_t *snap,
                       uint64_t B, const uint8_t chain32[32], owed_t *o,
                       uint64_t *counted_out) {
    memset(o, 0, sizeof(*o));
    o->self_bond_min = UINT64_MAX;
    if (q_u64(w, "SELECT reward_pool FROM supply_tracking WHERE id = 1",
              &o->pool) != 0)
        return -1;
    const uint64_t payout = o->pool >> NODUS_V2_GEN_REWARD_DIVISOR_LOG2;
    const uint64_t src = B >= 3 * E_LEN ? B - 3 * E_LEN : 0;
    const uint16_t n = snap->active_count;
    const int v2 = snap->selection_ruleset == DNA_VSET_RULESET_TOPN_V2;
    if (n == 0 || n > DNA_MAX_ACTIVE_VALIDATORS) return -1;
    uint64_t p[DNA_MAX_ACTIVE_VALIDATORS], c[DNA_MAX_ACTIVE_VALIDATORS];
    uint8_t (*ids)[64] = calloc(n, 64);
    nodus_v2_validator_row_t *row = calloc(1, sizeof(*row));
    int ret = -1;
    uint64_t sum = 0;
    if (!ids || !row) goto out;
    for (uint16_t i = 0; i < n; i++) {
        p[i] = snap->entries[i].total_stake / DNAC_DECIMAL_UNIT;
        memcpy(ids[i], snap->entries[i].validator_id, 64);
    }
    if (v2) {
        if (dna_power_cap_counted(p, (const uint8_t (*)[64])ids, n,
                                  DNAC_HF6_POWER_CAP_BPS_DEFAULT, c) != 0)
            goto out;
    } else {
        memcpy(c, p, (size_t)n * sizeof(*c));
    }
    for (uint16_t i = 0; i < n; i++) sum += c[i];
    if (counted_out) memcpy(counted_out, c, (size_t)n * sizeof(*c));
    o->members = n;
    for (uint16_t i = 0; i < n; i++) {
        const dna_vset_entry_t *e = &snap->entries[i];
        if (e->self_bond < o->self_bond_min) o->self_bond_min = e->self_bond;
        if (e->self_bond > o->self_bond_max) o->self_bond_max = e->self_bond;
        uint8_t vid[64];
        if (v2) memcpy(vid, e->validator_id, 64);
        else if (dna_validator_id_migrated(vid, chain32, e->pubkey) != 0)
            goto out;
        int rrc = nodus_validator_v2_get(w, vid, row);
        if (rrc < 0 || rrc > 1) goto out;
        const uint64_t share = sum ? muldiv(payout, c[i], sum) : 0;
        if (rrc == 1 || share == 0) continue;     /* unpaid: stays in pool */
        const uint64_t base = muldiv(share, e->self_bond, e->total_stake);
        const uint64_t gross = share - base;
        const uint64_t comm = muldiv(gross, e->commission_bps, 10000);
        const uint64_t net = gross - comm;
        if (owed_add(o, v2 ? e->owner_fp : row->owner_fp, base + comm) != 0)
            goto out;

        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db, "SELECT owner_fp, amount FROM "
                               "v2_balance_copy WHERE epoch_start = ?1 AND "
                               "validator_fp = ?2 AND kind = 1 ORDER BY "
                               "owner_fp ASC", -1, &st, NULL) != SQLITE_OK)
            goto out;
        sqlite3_bind_int64(st, 1, (sqlite3_int64)src);
        sqlite3_bind_blob(st, 2, vid, 64, SQLITE_TRANSIENT);
        uint8_t dfp[8][64];
        uint64_t a[8], sum_d = 0;
        int nd = 0, rc;
        while ((rc = sqlite3_step(st)) == SQLITE_ROW && nd < 8) {
            if (sqlite3_column_bytes(st, 0) != 64) break;
            memcpy(dfp[nd], sqlite3_column_blob(st, 0), 64);
            a[nd] = (uint64_t)sqlite3_column_int64(st, 1);
            sum_d += a[nd];
            nd++;
        }
        sqlite3_finalize(st);
        if (rc != SQLITE_DONE) goto out;
        if (sum_d != e->total_stake - e->self_bond) goto out;   /* gate */
        if (net > 0 && sum_d > 0)
            for (int d = 0; d < nd; d++)
                if (owed_add(o, dfp[d], muldiv(net, a[d], sum_d)) != 0)
                    goto out;
    }
    for (size_t i = 0; i < o->n; i++)
        if (accrual_of(w, o->fp[i], &o->before[i], NULL) != 0) goto out;
    ret = 0;
out:
    free(ids);
    free(row);
    return ret;
}

/* index of the entry holding key k's pubkey, or -1 */
static int entry_of(const dna_vset_snapshot_t *s, int k) {
    for (uint16_t i = 0; i < s->active_count; i++)
        if (memcmp(s->entries[i].pubkey, g_k[k].pk, PKLEN) == 0) return i;
    return -1;
}

/* An UNSTAKED v2 row (zero amounts) holding key k's consensus pubkey under
 * its own validator_id — a graduated row whose key was STAKEd again (§4,
 * slice-4 fault 2). The validators row through the CRUD writer (its key
 * column is whatever that writer derives), its roles row by SQL. */
static int put_unstaked_twin(nodus_witness_t *w, int k,
                             const uint8_t owner[64], uint8_t id_out[64]) {
    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, g_k[k].pk, PKLEN);
    v.commission_bps = COMM_BPS;
    v.status = DNAC_VALIDATOR_UNSTAKED;
    v.active_since_block = 1;
    memcpy(v.unstake_destination_fp, g_k[k].hex, 129);
    if (nodus_validator_insert(w, &v) != 0) return -1;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, "SELECT pubkey_hash FROM validators WHERE "
                           "status = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int(st, 1, (int)DNAC_VALIDATOR_UNSTAKED);
    int ok = sqlite3_step(st) == SQLITE_ROW &&
             sqlite3_column_bytes(st, 0) == 64;
    if (ok) memcpy(id_out, sqlite3_column_blob(st, 0), 64);
    ok = ok && sqlite3_step(st) == SQLITE_DONE;      /* the only UNSTAKED */
    sqlite3_finalize(st);
    if (!ok) return -1;
    st = NULL;
    if (sqlite3_prepare_v2(w->db, "INSERT INTO v2_validator_roles "
                           "(validator_id, owner_fp, pending_consensus_pubkey,"
                           " consensus_key_effective_epoch) VALUES (?1, ?2, "
                           "zeroblob(2592), 0)", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_blob(st, 1, id_out, 64, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, owner, 64, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* settlement_apply directly at boundary B inside a transaction that is
 * ALWAYS rolled back; `o` (when non-NULL) is checked before the rollback. */
static int settle_rolled_back(nodus_witness_t *w, uint64_t B, uint32_t gen,
                              const owed_t *o, uint64_t *acc_out) {
    uint64_t acc = 0;
    int rc = nodus_witness_v2_settlement_apply(w, B, gen, NULL, NULL, &acc);
    int chk = (rc == 0 && o) ? owed_check(w, o) : 0;
    if (acc_out) *acc_out = acc;
    if (run_sql(w->db, "ROLLBACK") != 0) return 99;
    if (rc != 0) return rc;
    if (o && acc != o->total) {
        fprintf(stderr, "accrued %llu, restated %llu\n",
                (unsigned long long)acc, (unsigned long long)o->total);
        return 98;
    }
    return chk == 0 ? 0 : 97;
}

static int t_engine_v2_snapshot(void) {
    fixture_t O;
    uint64_t h = 0;
    const uint64_t B = 5 * E_LEN;              /* governed by snapshot(4E) */
    CHECK(keys_make() == 0, "keys");
    CHECK(fx_open(&O, "v2s", 1, 0, 0) == 0, "seeded chain (fixture B shape, "
          "no RETIRING row)");
    {
        uint64_t iv = 0;
        CHECK(nodus_witness_v2_payout_interval(O.w, &iv) == 0 && iv >= 6,
              "no payday inside 1..5E");
    }
    CHECK(run_to(&O, NULL, &h, B - 1) == 0, "blocks 1..5E-1 (gen-4 edge in "
          "block H14-1; every block governed by an engine-built ruleset-1 "
          "snapshot)");
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    CHECK(nodus_witness_v2_chain_id(O.w, chain32) == 0, "chain id");
    nodus_v2_validator_row_t *row = calloc(1, sizeof(*row));
    CHECK(row != NULL, "alloc");

    /* ── E1. the builder at generation 4 ─────────────────────────────── */
    {
        nodus_committee_member_t *m =
            calloc(DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*m));
        dna_vset_snapshot_t *st5 = NULL, *b2 = NULL;
        int cnt = 0;
        CHECK(m != NULL, "alloc");
        CHECK(nodus_committee_compute_for_epoch(O.w, B, NODUS_RT_GEN_STORAGE,
                                                m,
                                                DNAC_MAX_ACTIVE_VALIDATORS,
                                                &cnt) == 0 && cnt == N_VAL,
              "the gen-4 core re-selects the seven for 5E");
        CHECK(nodus_witness_vset_get(O.w, B, &st5, NULL) == 0 &&
              st5->active_count == N_VAL &&
              st5->selection_ruleset == DNA_VSET_RULESET_TOPN_V2,
              "the stored snapshot(5E), built at the generation-4 boundary "
              "4E, is ruleset 2 (HF-6 5d)");
        b2 = dna_vset_alloc((uint16_t)cnt);
        CHECK(b2 != NULL, "alloc");
        b2->epoch = B;
        b2->selection_ruleset = DNA_VSET_RULESET_TOPN_V2;
        for (int i = 0; i < cnt; i++) {
            const dna_vset_entry_t *se = &st5->entries[i];
            uint8_t vid[64];
            CHECK(memcmp(m[i].pubkey, se->pubkey, PKLEN) == 0 &&
                  m[i].total_stake == se->total_stake &&
                  m[i].self_stake == se->self_bond,
                  "the core's order and amounts are the stored snapshot's");
            CHECK(dna_validator_id_migrated(vid, chain32, m[i].pubkey) == 0 &&
                  nodus_validator_v2_get(O.w, vid, row) == 0, "the row");
            CHECK(memcmp(m[i].validator_id, vid, 64) == 0 &&
                  memcmp(m[i].owner_fp, row->owner_fp, 64) == 0,
                  "gen 4: emit_member carries the row's validator_id and "
                  "owner_fp");
            CHECK(memcmp(se->validator_id, vid, 64) == 0 &&
                  memcmp(se->owner_fp, row->owner_fp, 64) == 0,
                  "the stored entry carries the same ids");
            CHECK(nodus_witness_vset_entry_from_member(
                      &m[i], DNA_VSET_RULESET_TOPN_V2, &b2->entries[i]) == 0,
                  "fill a ruleset-2 entry");
            CHECK(memcmp(b2->entries[i].voter_id, se->voter_id, 32) == 0 &&
                  memcmp(b2->entries[i].pubkey, se->pubkey, PKLEN) == 0 &&
                  b2->entries[i].total_stake == se->total_stake &&
                  b2->entries[i].self_bond == se->self_bond &&
                  b2->entries[i].commission_bps == se->commission_bps,
                  "the entry fill reproduces the stored entry");
        }
        {
            uint8_t hb[64], hs[64];
            CHECK(dna_vset_hash_ex(b2, DNA_VSET_RULESET_TOPN_V2, hb) == 0 &&
                  dna_vset_hash_ex(st5, DNA_VSET_RULESET_TOPN_V2, hs) == 0 &&
                  memcmp(hb, hs, 64) == 0,
                  "the member fill hashes to the stored snapshot's hash");
        }
        {
            /* get_for_block returns the ids ZERO (D6), hit and miss */
            nodus_committee_member_t *g = NULL;
            int gn = 0;
            static const uint8_t z[64] = { 0 };
            O.w->cached_committee_epoch_start = UINT64_MAX;  /* force miss */
            for (int pass = 0; pass < 2; pass++) {
                CHECK(nodus_committee_get_for_block_alloc(O.w, B - 1, &g,
                                                          &gn) == 0 &&
                      gn == N_VAL, "get_for_block (miss, then hit)");
                for (int i = 0; i < gn; i++)
                    CHECK(memcmp(g[i].validator_id, z, 64) == 0 &&
                          memcmp(g[i].owner_fp, z, 64) == 0,
                          "get_for_block: ids zero on the miss and the hit");
                free(g);
                g = NULL;
            }
        }
        dna_vset_free(&b2);
        dna_vset_free(&st5);
        free(m);
        /* leave no warm committee cache behind the snapshot rewrites */
        O.w->cached_committee_epoch_start = UINT64_MAX;
    }

    /* the governing snapshot(4E) — built at the generation-4 boundary 3E,
     * so the engine's own ruleset-2 row (HF-6 5d); E2/E4/E5 mutate
     * decoded copies of it */
    dna_vset_snapshot_t *T = stored_v2(O.w, 4 * E_LEN, chain32);
    CHECK(T != NULL && T->active_count == N_VAL,
          "the stored snapshot(4E) is ruleset 2 with the rows' ids");
    const int i0 = entry_of(T, V0), i1 = entry_of(T, V1), i2 = entry_of(T, V2);
    CHECK(i0 >= 0 && i1 >= 0 && i2 >= 0, "V0, V1, V2 seated in 4E");

    /* ── E2. a v2 entry whose owner_fp is not its row's → -2 ─────────── */
    {
        dna_vset_snapshot_t *s = stored_v2(O.w, 4 * E_LEN, chain32);
        CHECK(s != NULL, "twin");
        s->entries[i1].owner_fp[0] ^= 0x01;
        CHECK(run_sql(O.w->db, "BEGIN IMMEDIATE") == 0 &&
              snap_overwrite(O.w, s) == 0, "store the mismatched twin");
        CHECK(settle_rolled_back(O.w, B, NODUS_RT_GEN_STORAGE, NULL, NULL)
                  == -2, "an entry owner_fp differing from the row: FAULT");
        dna_vset_free(&s);
    }

    /* ── E3. a ruleset-2 snapshot paid below generation 4 → -2 ───────── */
    {
        CHECK(run_sql(O.w->db, "BEGIN IMMEDIATE") == 0,
              "the stored ruleset-2 snapshot(4E) governs 5E");
        CHECK(settle_rolled_back(O.w, B, NODUS_RT_GEN_STORAGE - 1, NULL,
                                 NULL) == -2,
              "ruleset 2 with a key generation below 4: FAULT");
    }

    /* ── E4. a v2 entry with no row: unpaid, its share stays in the pool;
     * its copy(2E) rows are re-keyed to the phantom id so the
     * consistency gate holds (kind-0 owner column = the id, §7.4). ─── */
    {
        dna_vset_snapshot_t *s = stored_v2(O.w, 4 * E_LEN, chain32);
        uint8_t phantom[64], real[64];
        CHECK(s != NULL, "twin");
        memcpy(real, s->entries[i2].validator_id, 64);
        memset(phantom, 0x7E, sizeof(phantom));
        CHECK(nodus_validator_v2_get(O.w, phantom, row) == 1,
              "the phantom id names no row");
        memcpy(s->entries[i2].validator_id, phantom, 64);
        CHECK(run_sql(O.w->db, "BEGIN IMMEDIATE") == 0 &&
              snap_overwrite(O.w, s) == 0, "store");
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(O.w->db, "INSERT INTO v2_balance_copy "
                      "(epoch_start, validator_fp, owner_fp, kind, amount) "
                      "SELECT epoch_start, ?1, CASE WHEN kind = 0 THEN ?1 "
                      "ELSE owner_fp END, kind, amount FROM v2_balance_copy "
                      "WHERE epoch_start = ?2 AND validator_fp = ?3", -1, &st,
                      NULL) == SQLITE_OK, "prepare");
            sqlite3_bind_blob(st, 1, phantom, 64, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 2, (sqlite3_int64)(2 * E_LEN));
            sqlite3_bind_blob(st, 3, real, 64, SQLITE_TRANSIENT);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            CHECK(rc == SQLITE_DONE && sqlite3_changes(O.w->db) >= 2,
                  "copy(2E) rows for the phantom id (bond + delegation)");
        }
        owed_t o;
        uint64_t acc = 0;
        CHECK(expect_snap(O.w, s, B, chain32, &o, NULL) == 0,
              "restated split (the phantom unpaid)");
        CHECK(settle_rolled_back(O.w, B, NODUS_RT_GEN_STORAGE, &o, &acc)
                  == 0, "a v2 entry with no row: applied, exactly the "
                  "restated deltas");
        {
            /* the phantom's share is NOT in Σ: the same snapshot with the
             * real id pays strictly more */
            owed_t full;
            CHECK(expect_snap(O.w, T, B, chain32, &full, NULL) == 0 &&
                  full.total > acc, "the phantom's share stayed in the pool");
        }
        dna_vset_free(&s);
    }

    /* ── E5. K2 through settlement_apply: V0 raised to 60M whole coins
     * (a 46M delegation from a new owner in copy(2E)), the rest 10M —
     * counted [25714285, 10M × 6] at 3000 bps (design §5 rule: k = 0
     * S = 120M c = 36M < 60M; k = 1 S = 60M c = ⌊3000·60M / 7000⌋ =
     * 25714285 ≥ 10M, stop). Shares by counted / Σcounted; V0's inner
     * split on its RAW 60M. ──────────────────────────────────────── */
    {
        dna_vset_snapshot_t *s = stored_v2(O.w, 4 * E_LEN, chain32);
        uint8_t nfp[64];
        const uint64_t add = 46 * TEN_M / 10;              /* 46M raw  */
        CHECK(s != NULL && fp_of(0x5A, nfp) == 0, "twin");
        CHECK(s->entries[i0].total_stake == TWO_M + EIGHT_M + KD_AMT,
              "FIXTURE GUARD: V0 holds 14M in snapshot(4E)");
        s->entries[i0].total_stake += add;                 /* 60M      */
        CHECK(run_sql(O.w->db, "BEGIN IMMEDIATE") == 0 &&
              snap_overwrite(O.w, s) == 0, "store");
        {
            sqlite3_stmt *st = NULL;
            CHECK(sqlite3_prepare_v2(O.w->db, "INSERT INTO v2_balance_copy "
                      "(epoch_start, validator_fp, owner_fp, kind, amount) "
                      "VALUES (?1, ?2, ?3, 1, ?4)", -1, &st, NULL)
                  == SQLITE_OK, "prepare");
            sqlite3_bind_int64(st, 1, (sqlite3_int64)(2 * E_LEN));
            sqlite3_bind_blob(st, 2, s->entries[i0].validator_id, 64,
                              SQLITE_TRANSIENT);
            sqlite3_bind_blob(st, 3, nfp, 64, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 4, (sqlite3_int64)add);
            int rc = sqlite3_step(st);
            sqlite3_finalize(st);
            CHECK(rc == SQLITE_DONE, "the 46M delegation row in copy(2E)");
        }
        owed_t o;
        uint64_t counted[DNA_MAX_ACTIVE_VALIDATORS];
        CHECK(expect_snap(O.w, s, B, chain32, &o, counted) == 0,
              "restated split");
        for (int i = 0; i < N_VAL; i++)
            CHECK(counted[i] == (i == i0 ? 25714285ULL : 10000000ULL),
                  "the counted vector [25714285, 10M × 6]");
        {
            uint64_t pw[DNA_MAX_ACTIVE_VALIDATORS];
            CHECK(nodus_witness_vset_powers(O.w, s, pw) == 0 &&
                  memcmp(pw, counted, N_VAL * sizeof(pw[0])) == 0,
                  "the witness helper agrees on the stored snapshot");
        }
        uint64_t n_amt = 0;
        CHECK(owed_of(&o, nfp, &n_amt) == 0 && n_amt > 0,
              "the new delegator is owed a share of V0's net");
        CHECK(settle_rolled_back(O.w, B, NODUS_RT_GEN_STORAGE, &o, NULL)
                  == 0, "Σcounted denominator, raw inner split: exactly "
                  "the restated deltas");
        dna_vset_free(&s);
    }

    /* ── E6. an UNSTAKED row sharing V1's consensus pubkey: the
     * ruleset-1 bridge and the ruleset-2 arm resolve by id and pay (the
     * by-pubkey read that faulted here, slice-4 fault 2, is deleted —
     * no production caller). ──────────────────────────────────────── */
    {
        uint8_t uid[64];
        owed_t o;
        CHECK(run_sql(O.w->db, "BEGIN IMMEDIATE") == 0 &&
              put_unstaked_twin(O.w, V1, g_k[KD].fp, uid) == 0,
              "the UNSTAKED twin row");
        /* HF-6 5d: every snapshot this chain built after its edge is
         * ruleset 2, so the ruleset-1 governing snapshot a post-H
         * boundary still reads (snapshot(B₀) at B₀ + E) is written here by
         * hand: snapshot(4E) in the v1 layout, inside this rolled-back
         * transaction. Case F crosses the real one. */
        dna_vset_snapshot_t *s1 = stored_v2(O.w, 4 * E_LEN, chain32);
        CHECK(s1 != NULL, "snapshot(4E)");
        to_v1(s1);
        CHECK(snap_overwrite(O.w, s1) == 0, "store its ruleset-1 shape");
        CHECK(expect_snap(O.w, s1, B, chain32, &o, NULL) == 0, "restated");
        dna_vset_free(&s1);
        CHECK(settle_rolled_back(O.w, B, NODUS_RT_GEN_STORAGE, &o, NULL)
                  == 0, "the v1 bridge (v2_get of the migrated id) pays "
                  "despite the shared pubkey");
    }

    /* ── E7. THROUGH THE ENGINE: the engine's own ruleset-2 snapshot(4E)
     * (every rewrite above was rolled back — re-checked) and the UNSTAKED
     * twin row committed before block 5E, then block 5E applies: base +
     * commission accrue to entry.owner_fp by validator_id. ─────────── */
    {
        uint8_t uid[64];
        owed_t o;
        {
            dna_vset_snapshot_t *again = stored_v2(O.w, 4 * E_LEN, chain32);
            uint8_t ha[64], ht[64];
            CHECK(again != NULL &&
                  dna_vset_hash_ex(again, DNA_VSET_RULESET_TOPN_V2, ha) == 0
                  && dna_vset_hash_ex(T, DNA_VSET_RULESET_TOPN_V2, ht) == 0
                  && memcmp(ha, ht, 64) == 0,
                  "the stored snapshot(4E) is the engine's again");
            dna_vset_free(&again);
        }
        CHECK(put_unstaked_twin(O.w, V1, g_k[KD].fp, uid) == 0,
              "the UNSTAKED twin row, committed");
        CHECK(expect_snap(O.w, T, B, chain32, &o, NULL) == 0, "restated");
        CHECK(o.members == N_VAL && o.self_bond_min == TWO_M &&
              o.self_bond_max == TWO_M, "seven members, post-H self_bond");
        CHECK(run_to(&O, NULL, &h, B) == 0, "block 5E applies (no FAULT)");
        CHECK(owed_check(O.w, &o) == 0,
              "every accrual moved by exactly the restated amount");
        uint64_t fa = 0, kd = 0;
        CHECK(owed_of(&o, k_found, &fa) == 0 && fa > 0,
              "base + commission (+ the 8M share) to entry.owner_fp — the "
              "Foundation owner");
        CHECK(owed_of(&o, g_k[KD].fp, &kd) == 0 && kd > 0, "KD's share");
        CHECK(o.n == 2, "nobody else is owed anything");
        for (int i = 0; i < N_VAL; i++) {
            uint64_t a = 0;
            int present = 1;
            CHECK(accrual_of(O.w, g_k[i].fp, &a, &present) == 0 && !present,
                  "no node-key accrual row");
        }
    }

    dna_vset_free(&T);
    free(row);
    fx_close(&O);
    return 0;
}

/* ══ F. HF-6 slice 5d — the v1 → v2 switch through the engine ══════════
 *
 * See the file header, case F. Helpers first. */

/* The stored row of epoch e: its blob (heap, caller frees) and hash. */
static int snap_row(nodus_witness_t *w, uint64_t e, uint8_t **blob,
                    size_t *len, uint8_t hash[64]) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    *blob = NULL;
    *len = 0;
    if (sqlite3_prepare_v2(w->db, "SELECT snapshot_blob, snapshot_hash FROM "
                           "validator_set_snapshots WHERE epoch_start = ?1",
                           -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)e);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) > 0 &&
        sqlite3_column_bytes(st, 1) == 64) {
        const int n = sqlite3_column_bytes(st, 0);
        *blob = malloc((size_t)n);
        if (*blob) {
            memcpy(*blob, sqlite3_column_blob(st, 0), (size_t)n);
            memcpy(hash, sqlite3_column_blob(st, 1), 64);
            *len = (size_t)n;
            ok = 0;
        }
    }
    sqlite3_finalize(st);
    return ok;
}

/* The selection_ruleset field of the stored row of epoch e, read from
 * the blob bytes 10..13 (big-endian u32 — shared/dnac/vset_wire.c, the
 * header epoch u64 ‖ active_count u16 ‖ ruleset u32). 0 on any failure. */
static uint32_t stored_ruleset(nodus_witness_t *w, uint64_t e) {
    uint8_t *b = NULL, h[64];
    size_t n = 0;
    uint32_t r = 0;
    if (snap_row(w, e, &b, &n, h) == 0 && n >= 14)
        r = ((uint32_t)b[10] << 24) | ((uint32_t)b[11] << 16) |
            ((uint32_t)b[12] << 8) | (uint32_t)b[13];
    free(b);
    return r;
}

/* the committed Comet BlockID at height h (the gen-4 tiebreak's seed for
 * e_start = h + E + 1 — nodus_witness_committee.c v2_seed_block_id) */
static int seed_at(nodus_witness_t *w, uint64_t h, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT block_id FROM v2_blocks WHERE "
                           "global_height = ?1", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    if (sqlite3_step(st) == SQLITE_ROW && sqlite3_column_bytes(st, 0) == 64) {
        memcpy(out, sqlite3_column_blob(st, 0), 64);
        ok = 0;
    }
    sqlite3_finalize(st);
    return ok;
}

#define KB_AMT  (46 * MIL)      /* V0: 10M + KD 4M + KB 46M = 60M raw */

static int t_engine_switch(void) {
    fixture_t A, Bf;
    uint64_t h = 0, iv = 0;
    /* B₀ = the first multiple of E strictly above H = H14 (the param-18
     * row's effective block; the edge flips the registry in H14 − 1) */
    const uint64_t B0 = (H14 / E_LEN + 1) * E_LEN;
    CHECK(E_LEN >= 8 && B0 == E_LEN, "FIXTURE GUARD: H14 < E, so B₀ = E");
    CHECK(keys_make() == 0, "keys");
    CHECK(fx_open(&A, "swa", 1, 0, KB_AMT) == 0 &&
          fx_open(&Bf, "swb", 1, 0, KB_AMT) == 0,
          "twin seeded chains, V0 at 60M (KD 4M + KB 46M at genesis)");
    CHECK(nodus_witness_v2_payout_interval(A.w, &iv) == 0 && iv >= 4,
          "no payday inside 1..3E");
    CHECK(A.w->v2_successor, "a version-3 chain (the Comet seed path)");
    uint8_t chain32[DNA_CHAIN_ID_LEN];
    CHECK(nodus_witness_v2_chain_id(A.w, chain32) == 0, "chain id");

    /* ── F1. every snapshot <= B₀ is ruleset 1, and B₀'s boundary leaves
     * the rows it does not write byte for byte ──────────────────────── */
    uint8_t h0[64], hB0[64];
    {
        uint8_t *b = NULL;
        size_t n = 0;
        CHECK(run_to(&A, &Bf, &h, B0 - 1) == 0, "blocks 1..B₀-1 (the edge "
              "in block H14-1)");
        uint32_t g = 0;
        CHECK(nodus_witness_v2_key_generation(A.w, &g) == 0 &&
              g == NODUS_RT_GEN_STORAGE, "generation 4 before B₀");
        CHECK(snap_row(A.w, 0, &b, &n, h0) == 0, "snapshot(0)");
        free(b);
        CHECK(snap_row(A.w, B0, &b, &n, hB0) == 0, "snapshot(B₀)");
        free(b);
        CHECK(stored_ruleset(A.w, 0) == DNA_VSET_RULESET_TOPN_V1 &&
              stored_ruleset(A.w, B0) == DNA_VSET_RULESET_TOPN_V1,
              "snapshot(0) and snapshot(B₀) are ruleset 1");
        CHECK(stored_ruleset(A.w, B0 + E_LEN) == 0,
              "no snapshot(B₀+E) before boundary B₀");
    }
    CHECK(run_to(&A, &Bf, &h, B0) == 0, "boundary B₀ applies on both twins");
    {
        uint8_t *b = NULL, x[64];
        size_t n = 0;
        CHECK(snap_row(A.w, 0, &b, &n, x) == 0 && memcmp(x, h0, 64) == 0,
              "snapshot(0) unchanged");
        free(b);
        CHECK(snap_row(A.w, B0, &b, &n, x) == 0 && memcmp(x, hB0, 64) == 0 &&
              stored_ruleset(A.w, B0) == DNA_VSET_RULESET_TOPN_V1,
              "snapshot(B₀) unchanged, still ruleset 1");
        free(b);
    }

    /* ── F2. snapshot(B₀+E): the first ruleset-2 blob ────────────────── */
    dna_vset_snapshot_t *sN = NULL, *sO = NULL;
    CHECK(stored_ruleset(A.w, B0 + E_LEN) == DNA_VSET_RULESET_TOPN_V2 &&
          stored_ruleset(Bf.w, B0 + E_LEN) == DNA_VSET_RULESET_TOPN_V2,
          "snapshot(B₀+E) — stored by the first boundary reading "
          "generation 4 — is ruleset 2 on both twins");
    sN = stored_v2(A.w, B0 + E_LEN, chain32);
    CHECK(sN != NULL && sN->active_count == N_VAL, "its seven entries carry "
          "the migrated validator_id and the roles row's owner_fp");
    {
        nodus_v2_validator_row_t *r = calloc(1, sizeof(*r));
        CHECK(r != NULL, "alloc");
        for (uint16_t i = 0; i < sN->active_count; i++)
            CHECK(nodus_validator_v2_get(A.w, sN->entries[i].validator_id, r)
                      == 0 &&
                  memcmp(r->owner_fp, k_found, 64) == 0 &&
                  memcmp(r->rec.pubkey, sN->entries[i].pubkey, PKLEN) == 0,
                  "each id names its roles row (Foundation-owned, same key)");
        free(r);
    }
    CHECK(entry_of(sN, V0) == 0 &&
          sN->entries[0].total_stake == TEN_M + KD_AMT + KB_AMT,
          "V0 first, at 60M");
    {
        /* the six equal 10M seats in SHA3-512(0x02 ‖ validator_id ‖ seed)
         * ASC, seed = the Comet BlockID at B₀ − 1 — the 129-byte
         * preimage built here byte by byte */
        uint8_t seed[64], pre[129], hc[64];
        uint8_t hp[64] = { 0 };
        CHECK(seed_at(A.w, B0 - 1, seed) == 0, "the lookback BlockID");
        for (uint16_t i = 1; i < sN->active_count; i++) {
            CHECK(sN->entries[i].total_stake == TEN_M, "10M seat");
            pre[0] = 0x02;
            memcpy(pre + 1, sN->entries[i].validator_id, 64);
            memcpy(pre + 65, seed, 64);
            CHECK(qgp_sha3_512(pre, sizeof(pre), hc) == 0, "sha3");
            if (i > 1)
                CHECK(memcmp(hp, hc, 64) < 0,
                      "equal seats ordered by the validator_id tiebreak");
            memcpy(hp, hc, 64);
        }
    }

    /* ── F3. §12g under ruleset 2: the preview at the boundary's
     * generation over the post-boundary state IS the stored blob ────── */
    {
        dna_vset_snapshot_t *pv = NULL;
        uint8_t *b = NULL, x[64], hpv[64];
        size_t n = 0;
        CHECK(nodus_witness_vset_preview_next(A.w, B0, NODUS_RT_GEN_STORAGE,
                                              &pv) == 0 && pv,
              "preview_next(B₀) at generation 4 builds");
        CHECK(pv->selection_ruleset == DNA_VSET_RULESET_TOPN_V2,
              "the preview is ruleset 2");
        const size_t need = dna_vset_encoded_len_ex(pv,
                                                    DNA_VSET_RULESET_TOPN_V2);
        uint8_t *enc = need ? malloc(need) : NULL;
        CHECK(enc != NULL && dna_vset_encode_ex(pv, DNA_VSET_RULESET_TOPN_V2,
                                                enc, need, NULL) == 0,
              "encode the preview");
        CHECK(snap_row(A.w, B0 + E_LEN, &b, &n, x) == 0 && n == need &&
              memcmp(b, enc, n) == 0,
              "preview bytes == stored snapshot(B₀+E) bytes");
        CHECK(dna_vset_hash_ex(pv, DNA_VSET_RULESET_TOPN_V2, hpv) == 0 &&
              memcmp(hpv, x, 64) == 0, "and its hash == the stored hash");
        free(enc);
        free(b);
        dna_vset_free(&pv);
    }

    /* ── F4. the Comet update at B₀+E, RESTATED: FinalizeBlock's diff
     * (nodus_witness_cmt_app.c) matches entries by pubkey and takes each
     * side's power from nodus_witness_vset_powers by its own ruleset —
     * the same two calls, the same match, here. ───────────────────────── */
    {
        uint64_t pN[DNA_MAX_ACTIVE_VALIDATORS], pO[DNA_MAX_ACTIVE_VALIDATORS];
        uint64_t oracle[DNA_MAX_ACTIVE_VALIDATORS];
        uint64_t raw[DNA_MAX_ACTIVE_VALIDATORS];
        uint8_t ids[DNA_MAX_ACTIVE_VALIDATORS][64];
        int changed = 0, added = 0, removed = 0, v0_new = -1;
        CHECK(nodus_witness_vset_get(A.w, B0, &sO, NULL) == 0 && sO &&
              sO->selection_ruleset == DNA_VSET_RULESET_TOPN_V1,
              "the old side snapshot(B₀), ruleset 1");
        CHECK(nodus_witness_vset_powers(A.w, sN, pN) == 0 &&
              nodus_witness_vset_powers(A.w, sO, pO) == 0, "both sides");
        for (uint16_t i = 0; i < sN->active_count; i++) {
            raw[i] = sN->entries[i].total_stake / DNAC_DECIMAL_UNIT;
            memcpy(ids[i], sN->entries[i].validator_id, 64);
        }
        CHECK(dna_power_cap_counted(raw, (const uint8_t (*)[64])ids,
                                    sN->active_count,
                                    DNAC_HF6_POWER_CAP_BPS_DEFAULT,
                                    oracle) == 0 &&
              memcmp(oracle, pN, sN->active_count * sizeof(pN[0])) == 0,
              "the new side's helper output is the cap's (oracle-pinned) "
              "counted vector");
        /* design §5 at 3000 bps, [60M, 10M × 6] whole coins: k = 0
         * S = 120M c = 36M < 60M; k = 1 S = 60M c = ⌊3000·60M / 7000⌋ =
         * 25714285 ≥ 10M, stop (shared/dnac/power_cap.h rule) */
        for (uint16_t i = 0; i < sN->active_count; i++)
            CHECK(pN[i] == (i == 0 ? 25714285ULL : 10000000ULL),
                  "counted [25714285, 10M × 6]");
        for (uint16_t i = 0; i < sN->active_count; i++) {
            int found = 0;
            for (uint16_t j = 0; j < sO->active_count; j++)
                if (memcmp(sN->entries[i].pubkey, sO->entries[j].pubkey,
                           PKLEN) == 0) {
                    found = 1;
                    if (pO[j] != pN[i]) { changed++; v0_new = (int)i; }
                }
            if (!found) added++;
        }
        for (uint16_t j = 0; j < sO->active_count; j++) {
            int found = 0;
            for (uint16_t i = 0; i < sN->active_count; i++)
                if (memcmp(sN->entries[i].pubkey, sO->entries[j].pubkey,
                           PKLEN) == 0)
                    found = 1;
            if (!found) removed++;
        }
        CHECK(changed == 1 && added == 0 && removed == 0 && v0_new == 0,
              "exactly one power change (V0: raw 60000000 → counted "
              "25714285), no addition, no removal");
        {
            const int jo = entry_of(sO, V0);
            CHECK(jo >= 0 && pO[jo] == 60000000ULL,
                  "the old side is raw (ruleset 1 ⇒ identity)");
        }
    }

    /* ── F5. the last v1-governed distribution (B₀+E, snapshot(B₀) via
     * the migrated-id bridge) and the FIRST v2-governed one (B₀+2E,
     * snapshot(B₀+E) by validator_id, counted / Σcounted, entry
     * owner_fp) — each exactly the restated deltas on both twins ───── */
    for (int step = 1; step <= 2; step++) {
        const uint64_t Bh = B0 + (uint64_t)step * E_LEN;
        owed_t o;
        uint64_t counted[DNA_MAX_ACTIVE_VALIDATORS];
        CHECK(run_to(&A, &Bf, &h, Bh - 1) == 0, "idle to B-1");
        CHECK(expect_snap(A.w, step == 1 ? sO : sN, Bh, chain32, &o,
                          counted) == 0, "restated split");
        if (step == 2)
            CHECK(counted[0] == 25714285ULL,
                  "B₀+2E shares by the counted power");
        else
            CHECK(counted[entry_of(sO, V0)] == 60000000ULL,
                  "B₀+E shares by the raw power");
        CHECK(run_to(&A, &Bf, &h, Bh) == 0, "the boundary applies");
        CHECK(owed_check(A.w, &o) == 0 && owed_check(Bf.w, &o) == 0,
              "every accrual moved by exactly the restated amount");
        uint64_t fa = 0, kd = 0, kb = 0;
        CHECK(owed_of(&o, k_found, &fa) == 0 && fa > 0,
              "base + commission to the Foundation owner");
        CHECK(owed_of(&o, g_k[KD].fp, &kd) == 0 && kd > 0 &&
              owed_of(&o, g_k[KB].fp, &kb) == 0 && kb > kd,
              "KD's and KB's delegation shares (KB's larger)");
        CHECK(o.n == 3, "nobody else is owed anything");
        for (int i = 0; i < N_VAL; i++) {
            uint64_t a = 0;
            int present = 1;
            CHECK(accrual_of(A.w, g_k[i].fp, &a, &present) == 0 && !present,
                  "no node-key accrual row");
        }
        CHECK(stored_ruleset(A.w, Bh + E_LEN) == DNA_VSET_RULESET_TOPN_V2,
              "every later snapshot is ruleset 2");
    }
    {
        uint8_t da[64], db[64];
        CHECK(v2x_db_digest(A.w, da) == 0 && v2x_db_digest(Bf.w, db) == 0 &&
              memcmp(da, db, 64) == 0, "twin databases byte-identical");
    }
    dna_vset_free(&sN);
    dna_vset_free(&sO);
    fx_close(&A);
    fx_close(&Bf);
    return 0;
}

/* ══ D. the reader inventory (a source scan) ═══════════════════════════ */

typedef struct {
    const char *file;
    const char *func;
    const char *pat;        /* SQL fragment or "callee(" */
    int         count;
    const char *cls;        /* ARMED / GEN4_ONLY:<caller> / V1_COMPOSITION /
                             * VALUE_SCAN / BOOTSTRAP */
} inv_t;

/* Plan tasks/hf6-slice3-plan.md §3: every reader of the re-keyed tables on
 * the boundary / root side, and why it is right under generation 4. */
static const inv_t k_inv[] = {
    /* roots: v4 composes the v1 loaders; v5 the v2 loaders, which read
     * through nodus_validator_v2_scan / nodus_delegation_v2_scan */
    { "nodus_witness_merkle.c", "load_validator_leaves", "FROM validators", 1,
      "V1_COMPOSITION" },
    { "nodus_witness_merkle.c", "load_delegation_leaves", "FROM delegations",
      1, "V1_COMPOSITION" },
    /* the frozen balance copy */
    { "nodus_witness_v2_econ.c", "nodus_witness_v2_balance_copy_write_gen",
      "FROM validators", 1, "ARMED" },
    { "nodus_witness_v2_econ.c", "nodus_witness_v2_balance_copy_write_gen",
      "FROM delegations", 1, "ARMED" },
    { "nodus_witness_v2_econ.c", "v2ec_copy_collect_g4", "FROM validators", 1,
      "GEN4_ONLY:nodus_witness_v2_balance_copy_write_gen" },
    { "nodus_witness_v2_econ.c", "v2ec_copy_collect_g4", "FROM delegations",
      1, "GEN4_ONLY:nodus_witness_v2_balance_copy_write_gen" },
    /* the distribution's member row */
    { "nodus_witness_v2_econ.c", "v2ec_member_load", "nodus_validator_get(",
      1, "ARMED" },
    /* commissions activate by value; graduation and its delegation release
     * are keyed; Rule N scans by status / pubkey */
    { "nodus_witness_v2_epoch.c", "v2ep_activate_commissions",
      "UPDATE validators", 1, "VALUE_SCAN" },
    { "nodus_witness_v2_epoch.c", "v2ep_release_delegations",
      "FROM delegations", 2, "ARMED" },
    { "nodus_witness_v2_epoch.c", "v2ep_graduate", "FROM validators", 1,
      "ARMED" },
    { "nodus_witness_v2_epoch.c", "v2ep_graduate", "nodus_validator_get(", 1,
      "ARMED" },
    { "nodus_witness_v2_epoch.c", "v2ep_graduate", "nodus_validator_update(",
      1, "ARMED" },
    { "nodus_witness_v2_epoch.c", "v2ep_rule_n", "FROM validators", 2,
      "VALUE_SCAN" },
    { "nodus_witness_v2_epoch.c", "v2ep_rule_n", "UPDATE validators", 2,
      "VALUE_SCAN" },
    /* committee: the genesis bootstrap ranks the live rows by value; the
     * post-bootstrap core is keyed (frozen copy) */
    { "nodus_witness_committee.c", "nodus_committee_bootstrap_for_epoch",
      "nodus_validator_top_n(", 1, "BOOTSTRAP" },
    { "nodus_witness_committee.c", "nodus_committee_compute_for_epoch",
      "nodus_validator_bonded_tenured(", 1, "ARMED" },
    { "nodus_witness_committee.c", "nodus_committee_compute_for_epoch",
      "nodus_witness_v2_balance_copy_frozen(", 1, "ARMED" },
    /* flips by status / pubkey, or pubkey_hash (= validator_id) under
     * ruleset 2 (HF-6 slice 6c: pass 1 + the two arms of pass 2); the
     * supply equation and the p2p bonded set by value */
    { "nodus_witness_vset.c", "nodus_witness_vset_apply_boundary_flips",
      "UPDATE validators", 3, "VALUE_SCAN" },
    { "nodus_witness_v2_claims.c", "nodus_rt_core_invariant",
      "FROM validators", 2, "VALUE_SCAN" },
    { "nodus_witness_p2p.c", "nodus_witness_p2p_refresh_bonded",
      "FROM validators", 1, "VALUE_SCAN" },
    /* HF-6 slice 6e: the pending consensus keys of ACTIVE / ELIGIBLE rows,
     * joined on pubkey_hash = v2_validator_roles.validator_id — by value
     * (status), node-local, empty below generation 4 */
    { "nodus_witness_p2p.c", "bonded_add_pending", "JOIN validators", 1,
      "VALUE_SCAN" },
};

static const char *k_files[] = {
    "nodus_witness_merkle.c", "nodus_witness_roots_v2.c",
    "nodus_witness_v2_econ.c", "nodus_witness_v2_epoch.c",
    "nodus_witness_committee.c", "nodus_witness_vset.c",
    "nodus_witness_v2_claims.c", "nodus_witness_p2p.c",
};

static const char *k_sql[] = {
    "FROM validators", "UPDATE validators", "INTO validators",
    "JOIN validators", "FROM delegations", "UPDATE delegations",
    "INTO delegations", "JOIN delegations",
};

/* the pubkey-keyed CRUD layer and the pre-HF-6 copy entries */
static const char *k_calls[] = {
    "nodus_validator_get", "nodus_validator_update", "nodus_validator_insert",
    "nodus_validator_bonded_tenured", "nodus_validator_top_n",
    "nodus_validator_list_paged", "nodus_delegation_get",
    "nodus_delegation_delete", "nodus_delegation_insert",
    "nodus_delegation_count_by_validator",
    "nodus_delegation_count_by_delegator",
    "nodus_delegation_list_by_delegator",
    "nodus_witness_v2_balance_copy_frozen",
    "nodus_witness_v2_balance_copy_write",
};

#define INV_MAX_HITS  512
#define INV_MAX_FUNCS 2048
typedef struct {
    char func[96];
    char pat[64];
} inv_hit_t;
typedef struct {
    char   name[96];
    int    armed;             /* body names NODUS_RT_GEN_STORAGE       */
    char  *idents;            /* every identifier in the body, ' '-sep */
    size_t ilen, icap;
} inv_func_t;

typedef struct {
    inv_hit_t  hits[INV_MAX_HITS];
    size_t     nh;
    inv_func_t funcs[INV_MAX_FUNCS];
    size_t     nf;
} inv_scan_t;

static int is_id(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static int inv_hit(inv_scan_t *s, const char *func, const char *pat) {
    if (s->nh == INV_MAX_HITS) return -1;
    snprintf(s->hits[s->nh].func, sizeof(s->hits[0].func), "%s",
             func ? func : "(file scope)");
    snprintf(s->hits[s->nh].pat, sizeof(s->hits[0].pat), "%s", pat);
    s->nh++;
    return 0;
}

/* the pending (adjacent, concatenated) string literal: scan for SQL */
static int inv_flush(inv_scan_t *s, char *lit, size_t *ll, int *pending,
                     const char *func) {
    if (!*pending) return 0;
    lit[*ll] = '\0';
    for (size_t p = 0; p < sizeof(k_sql) / sizeof(k_sql[0]); p++) {
        const size_t pl = strlen(k_sql[p]);
        for (const char *q = strstr(lit, k_sql[p]); q;
             q = strstr(q + pl, k_sql[p])) {
            if (is_id(q[pl])) continue;
            if (inv_hit(s, func, k_sql[p]) != 0) return -1;
        }
    }
    *ll = 0;
    *pending = 0;
    return 0;
}

static int inv_ident_add(inv_func_t *f, const char *id, size_t n) {
    if (f->ilen + n + 2 > f->icap) {
        size_t nc = f->icap ? f->icap * 2 : 4096;
        while (nc < f->ilen + n + 2) nc *= 2;
        char *nb = realloc(f->idents, nc);
        if (!nb) return -1;
        f->idents = nb;
        f->icap = nc;
    }
    memcpy(f->idents + f->ilen, id, n);
    f->ilen += n;
    f->idents[f->ilen++] = ' ';
    f->idents[f->ilen] = '\0';
    return 0;
}

/* Tokenise one C file: comments and preprocessor lines are skipped,
 * adjacent string literals are concatenated, the enclosing function of a
 * file-scope `name(...) {` is tracked by brace depth. */
static int inv_scan_file(inv_scan_t *s, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { fprintf(stderr, "inventory: cannot open %s\n", path);
               return -1; }
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0 || fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return -1; }
    char *src = malloc((size_t)sz + 1);
    char *lit = malloc((size_t)sz + 1);
    if (!src || !lit || fread(src, 1, (size_t)sz, fp) != (size_t)sz) {
        free(src); free(lit); fclose(fp); return -1;
    }
    fclose(fp);
    src[sz] = '\0';

    size_t n = (size_t)sz, i = 0, ll = 0;
    int depth = 0, pending = 0, ret = -1;
    char cand[96] = "";
    inv_func_t *cur = NULL;
    int bol = 1;                    /* at the beginning of a line         */
    while (i < n) {
        char c = src[i];
        if (c == '/' && i + 1 < n && src[i + 1] == '*') {
            const char *e = strstr(src + i + 2, "*/");
            i = e ? (size_t)(e - src) + 2 : n;
            continue;
        }
        if (c == '/' && i + 1 < n && src[i + 1] == '/') {
            while (i < n && src[i] != '\n') i++;
            continue;
        }
        if (c == '"') {
            size_t j = i + 1;
            while (j < n && src[j] != '"') {
                if (src[j] == '\\' && j + 1 < n) {
                    lit[ll++] = src[j]; lit[ll++] = src[j + 1]; j += 2;
                    continue;
                }
                lit[ll++] = src[j++];
            }
            pending = 1;
            i = j + 1;
            bol = 0;
            continue;
        }
        if (c == '\'') {
            size_t j = i + 1;
            while (j < n && src[j] != '\'') j += (src[j] == '\\') ? 2 : 1;
            i = j + 1;
            bol = 0;
            continue;
        }
        if (c == '\n') { bol = 1; i++; continue; }
        if (c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v') {
            i++;
            continue;
        }
        if (c == '#' && bol) {
            if (inv_flush(s, lit, &ll, &pending, cur ? cur->name : NULL)
                != 0) goto out;
            /* the whole directive, continuation lines included */
            while (i < n) {
                if (src[i] == '\n' && src[i - 1] != '\\') break;
                i++;
            }
            continue;
        }
        bol = 0;
        if (inv_flush(s, lit, &ll, &pending, cur ? cur->name : NULL) != 0)
            goto out;
        if (is_id(c) && !(c >= '0' && c <= '9')) {
            size_t j = i;
            while (j < n && is_id(src[j])) j++;
            const size_t idl = j - i;
            size_t k = j;
            while (k < n && (src[k] == ' ' || src[k] == '\t' ||
                             src[k] == '\n' || src[k] == '\r'))
                k++;
            const int call = k < n && src[k] == '(';
            if (depth > 0 && cur) {
                if (inv_ident_add(cur, src + i, idl) != 0) goto out;
                if (idl == strlen("NODUS_RT_GEN_STORAGE") &&
                    memcmp(src + i, "NODUS_RT_GEN_STORAGE", idl) == 0)
                    cur->armed = 1;
                if (call) {
                    for (size_t p = 0;
                         p < sizeof(k_calls) / sizeof(k_calls[0]); p++) {
                        if (strlen(k_calls[p]) == idl &&
                            memcmp(k_calls[p], src + i, idl) == 0) {
                            char pat[64];
                            snprintf(pat, sizeof(pat), "%s(", k_calls[p]);
                            if (inv_hit(s, cur->name, pat) != 0) goto out;
                        }
                    }
                }
            } else if (depth == 0 && call && idl < sizeof(cand)) {
                memcpy(cand, src + i, idl);
                cand[idl] = '\0';
            }
            i = j;
            continue;
        }
        if (c == '{') {
            if (depth == 0 && cand[0]) {
                if (s->nf == INV_MAX_FUNCS) goto out;
                cur = &s->funcs[s->nf++];
                memset(cur, 0, sizeof(*cur));
                snprintf(cur->name, sizeof(cur->name), "%s", cand);
            }
            depth++;
        } else if (c == '}') {
            depth--;
            if (depth == 0) { cur = NULL; cand[0] = '\0'; }
            if (depth < 0) goto out;
        } else if ((c == ';' || c == '=') && depth == 0) {
            cand[0] = '\0';
        }
        i++;
    }
    if (inv_flush(s, lit, &ll, &pending, cur ? cur->name : NULL) != 0)
        goto out;
    ret = depth == 0 ? 0 : -1;
out:
    free(src);
    free(lit);
    return ret;
}

static void inv_free(inv_scan_t *s) {
    for (size_t i = 0; i < s->nf; i++) free(s->funcs[i].idents);
    s->nf = 0;
    s->nh = 0;
}

static const inv_func_t *inv_func(const inv_scan_t *s, const char *name) {
    for (size_t i = 0; i < s->nf; i++)
        if (strcmp(s->funcs[i].name, name) == 0) return &s->funcs[i];
    return NULL;
}

static int t_reader_inventory(void) {
    inv_scan_t *s = calloc(1, sizeof(*s));
    CHECK(s != NULL, "alloc");
    int bad = 0;
    for (size_t f = 0; f < sizeof(k_files) / sizeof(k_files[0]); f++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", NODUS_HF6_READERS_SRC_DIR,
                 k_files[f]);
        inv_free(s);
        if (inv_scan_file(s, path) != 0) {
            fprintf(stderr, "inventory: %s did not tokenise\n", k_files[f]);
            bad = 1;
            continue;
        }
        /* every hit is classified, with its exact count */
        for (size_t h = 0; h < s->nh; h++) {
            int seen = 0, want = -1;
            for (size_t j = 0; j < s->nh; j++)
                if (strcmp(s->hits[j].func, s->hits[h].func) == 0 &&
                    strcmp(s->hits[j].pat, s->hits[h].pat) == 0)
                    seen++;
            for (size_t e = 0; e < sizeof(k_inv) / sizeof(k_inv[0]); e++)
                if (strcmp(k_inv[e].file, k_files[f]) == 0 &&
                    strcmp(k_inv[e].func, s->hits[h].func) == 0 &&
                    strcmp(k_inv[e].pat, s->hits[h].pat) == 0)
                    want = k_inv[e].count;
            if (want != seen) {
                fprintf(stderr, "inventory: %s %s: \"%s\" x%d is not "
                        "classified (pinned x%d) — decide its generation-4 "
                        "arm and pin it\n", k_files[f], s->hits[h].func,
                        s->hits[h].pat, seen, want);
                bad = 1;
            }
        }
        /* every pinned entry is still there; ARMED / GEN4_ONLY hold */
        for (size_t e = 0; e < sizeof(k_inv) / sizeof(k_inv[0]); e++) {
            if (strcmp(k_inv[e].file, k_files[f]) != 0) continue;
            int seen = 0;
            for (size_t j = 0; j < s->nh; j++)
                if (strcmp(s->hits[j].func, k_inv[e].func) == 0 &&
                    strcmp(s->hits[j].pat, k_inv[e].pat) == 0)
                    seen++;
            const inv_func_t *fn = inv_func(s, k_inv[e].func);
            if (seen != k_inv[e].count || !fn) {
                fprintf(stderr, "inventory: pinned %s %s \"%s\" x%d, found "
                        "x%d\n", k_files[f], k_inv[e].func, k_inv[e].pat,
                        k_inv[e].count, seen);
                bad = 1;
                continue;
            }
            if (strcmp(k_inv[e].cls, "ARMED") == 0 && !fn->armed) {
                fprintf(stderr, "inventory: %s is pinned ARMED but tests no "
                        "NODUS_RT_GEN_STORAGE\n", k_inv[e].func);
                bad = 1;
            }
            if (strncmp(k_inv[e].cls, "GEN4_ONLY:", 10) == 0) {
                const char *caller = k_inv[e].cls + 10;
                const inv_func_t *cf = inv_func(s, caller);
                char needle[128];
                snprintf(needle, sizeof(needle), " %s ", k_inv[e].func);
                char *hay = NULL;
                if (cf && cf->idents) {
                    hay = malloc(cf->ilen + 2);
                    if (hay) {
                        hay[0] = ' ';
                        memcpy(hay + 1, cf->idents, cf->ilen + 1);
                    }
                }
                if (!cf || !cf->armed || !hay || !strstr(hay, needle)) {
                    fprintf(stderr, "inventory: %s is GEN4_ONLY but its "
                            "caller %s is missing, not ARMED, or does not "
                            "call it\n", k_inv[e].func, caller);
                    bad = 1;
                }
                free(hay);
            }
        }
    }
    inv_free(s);
    free(s);
    CHECK(!bad, "every boundary / root reader of validators / delegations "
          "is classified and every keyed one has a generation-4 arm");
    return 0;
}

/* G. HF-6 slice 5d — no ruleset-1-only codec entry point is called from
 * nodus_witness_vset.c (the store, the read and the builder of every
 * snapshot), counted over the identifiers of every function body by the
 * same tokeniser as D (comments and string literals are not
 * identifiers). The `_ex` family must be seen (a positive control — a
 * scan that saw nothing would otherwise pass). */
static int t_codec_inventory(void) {
    static const char *legacy[] = {
        "dna_vset_hash", "dna_vset_decode", "dna_vset_encode",
        "dna_vset_hash_bytes", "dna_vset_encoded_len",
    };
    inv_scan_t *s = calloc(1, sizeof(*s));
    CHECK(s != NULL, "alloc");
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", NODUS_HF6_READERS_SRC_DIR,
             "nodus_witness_vset.c");
    CHECK(inv_scan_file(s, path) == 0, "nodus_witness_vset.c tokenises");
    int hits = 0, ex_seen = 0;
    for (size_t f = 0; f < s->nf; f++) {
        const inv_func_t *fn = &s->funcs[f];
        if (!fn->idents) continue;
        char *hay = malloc(fn->ilen + 2);
        CHECK(hay != NULL, "alloc");
        hay[0] = ' ';
        memcpy(hay + 1, fn->idents, fn->ilen + 1);
        for (size_t k = 0; k < sizeof(legacy) / sizeof(legacy[0]); k++) {
            char needle[64];
            snprintf(needle, sizeof(needle), " %s ", legacy[k]);
            if (strstr(hay, needle)) {
                fprintf(stderr, "codec inventory: %s calls %s\n", fn->name,
                        legacy[k]);
                hits++;
            }
        }
        if (strstr(hay, " dna_vset_hash_bytes_ex ")) ex_seen |= 1;
        if (strstr(hay, " dna_vset_decode_ex ")) ex_seen |= 2;
        if (strstr(hay, " dna_vset_encode_ex ")) ex_seen |= 4;
        free(hay);
    }
    inv_free(s);
    free(s);
    CHECK(ex_seen == 7, "the scan sees the _ex hash / decode / encode calls");
    CHECK(hits == 0, "zero ruleset-1-only codec calls in "
          "nodus_witness_vset.c");
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "leaf_bytes",          t_leaf_bytes },
        { "reader_inventory",    t_reader_inventory },
        { "engine_foundation",   t_engine_foundation },
        { "engine_own_owner",    t_engine_own_owner },
        { "engine_v2_snapshot",  t_engine_v2_snapshot },
        { "engine_switch",       t_engine_switch },
        { "codec_inventory",     t_codec_inventory },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "[%s] %s\n", rc == 0 ? "PASS" : "FAIL",
                cases[i].name);
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf6_readers: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed == 0 ? 0 : 1;
}
