/**
 * @file nodus/src/witness/nodus_witness_v2_preflight.c
 * @brief Ledger V2 O15A — activation-readiness preflight.
 *
 * Contract, the read-only guarantee and the stable issue ids are in
 * nodus_witness_v2_preflight.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_v2_preflight.h"

#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#include "dnac/vset_wire.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_schema.h"
#include "witness/nodus_witness_cmt_store.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "WITNESS_V2_PREFL"

/* Record an issue. Idempotent per id.
 *
 * O15A (reviewer R3): this used to claim the report was "ascending by
 * construction because the checks run in that order". That was FALSE on
 * two real paths — a genesis-identity mismatch (id 6) is added in the
 * genesis section BEFORE a missing manifest (id 5) can be added in the
 * next one, and INSPECTION_FAULT (id 14) is added at the point of fault,
 * ahead of any lower id a later section still adds. Canonical order is a
 * PINNED CONTRACT (two nodes must produce byte-identical reports), so it
 * is now established by an actual ordered insert rather than by an
 * argument about control flow that a future check could quietly break. */
static void pf_add(nodus_v2_preflight_report_t *r, nodus_v2_pf_issue_t id) {
    size_t i;
    for (i = 0; i < r->n_issues; i++) {
        if (r->issues[i] == id) return;        /* idempotent per id */
        if ((int)r->issues[i] > (int)id) break;
    }
    if (r->n_issues >= NODUS_V2_PF_MAX_ISSUES) return;
    for (size_t j = r->n_issues; j > i; j--)
        r->issues[j] = r->issues[j - 1];
    r->issues[i] = id;
    r->n_issues++;
}

const char *nodus_witness_v2_preflight_issue_name(nodus_v2_pf_issue_t id) {
    switch (id) {
    case NODUS_V2_PF_SCHEMA_UNSUPPORTED:        return "SCHEMA_UNSUPPORTED";
    case NODUS_V2_PF_SCHEMA_SHAPE_DRIFT:        return "SCHEMA_SHAPE_DRIFT";
    case NODUS_V2_PF_GENESIS_ABSENT:            return "GENESIS_ABSENT";
    case NODUS_V2_PF_GENESIS_MALFORMED:         return "GENESIS_MALFORMED";
    case NODUS_V2_PF_GENESIS_MANIFEST_ABSENT:   return "GENESIS_MANIFEST_ABSENT";
    case NODUS_V2_PF_GENESIS_IDENTITY_MISMATCH: return "GENESIS_IDENTITY_MISMATCH";
    case NODUS_V2_PF_CHAIN_ID_UNRESOLVABLE:     return "CHAIN_ID_UNRESOLVABLE";
    case NODUS_V2_PF_CHAIN_ID_DISAGREEMENT:     return "CHAIN_ID_DISAGREEMENT";
    case NODUS_V2_PF_VSET_SNAPSHOT_ABSENT:      return "VSET_SNAPSHOT_ABSENT";
    case NODUS_V2_PF_VSET_SNAPSHOT_INVALID:     return "VSET_SNAPSHOT_INVALID";
    case NODUS_V2_PF_SUPPLY_INCONSISTENT:       return "SUPPLY_INCONSISTENT";
    case NODUS_V2_PF_RULE_N_ATTENDANCE_SOURCE_ABSENT:
        return "RULE_N_ATTENDANCE_SOURCE_ABSENT";
    case NODUS_V2_PF_INGRESS_ENABLED:           return "INGRESS_ENABLED";
    case NODUS_V2_PF_INSPECTION_FAULT:          return "INSPECTION_FAULT";
    case NODUS_V2_PF_ACTIVATION_AUTHORITY_MALFORMED:
        return "ACTIVATION_AUTHORITY_MALFORMED";
    case NODUS_V2_PF_TARGET_MISMATCH:           return "TARGET_MISMATCH";
    case NODUS_V2_PF_GENESIS_APP_HASH_MISMATCH:
        return "GENESIS_APP_HASH_MISMATCH";
    }
    return "UNKNOWN";
}

/* 1 = present, 0 = absent, -1 = fault. A probe fault is NEVER "absent" —
 * the table_exists discipline (v2_apply.c:69-70). */
static int pf_table_exists(nodus_witness_t *w, const char *name) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW)  return 1;
    if (rc == SQLITE_DONE) return 0;
    return -1;
}

/* Row count, or -1 on fault. */
static sqlite3_int64 pf_count(nodus_witness_t *w, const char *sql) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    sqlite3_int64 n = (rc == SQLITE_ROW) ? sqlite3_column_int64(st, 0) : -1;
    sqlite3_finalize(st);
    return n;
}

int nodus_witness_v2_preflight(nodus_witness_t *w,
                               nodus_v2_preflight_report_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!w || !w->db) return -1;

    /* ── 1. SCHEMA ────────────────────────────────────────────────── */
    uint32_t ver = 0;
    if (nodus_witness_db_schema_version(w, &ver) != 0) {
        pf_add(out, NODUS_V2_PF_SCHEMA_UNSUPPORTED);
        pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
        out->ready = 0;
        return 0;
    }
    /* R3 W3 (D-17 rev 10 (8)) — THE LIVE S14 FLIP: S14 was the ONLY
     * accepted schema. Before this wave S10/S11/S12 were accepted because
     * the legacy consensus lane read them directly; that lane is CLOSED in
     * W3 (D-17 rev 10 (9)) and this build derives version-3 chains only,
     * which climb straight through S13 to S15 (nodus_witness_v2_gen_derive_v3).
     * A database at any earlier rung is not a chain this preflight can
     * ever call ready, so narrowing the accepted set to one value is not a
     * loss of coverage — it is the coverage this build actually has.
     * tokenomics-v3 P1: the ONE accepted value moves S14 -> S15. */
    if (ver != NODUS_V2_SCHEMA_VERSION_S15)
        pf_add(out, NODUS_V2_PF_SCHEMA_UNSUPPORTED);

    /* ── 2. REQUIRED TABLES ───────────────────────────────────────── */
    {
        /* O15J Faz 3 — "v2_activation" and "v2_activation_readiness" are
         * REMOVED from this list. The activation ceremony is gone and the
         * S10 migration no longer creates them, so requiring them would
         * raise SCHEMA_SHAPE_DRIFT on every database this tree can
         * produce — making `ready` false, the gate NOT_READY and the V2
         * lane permanently unarmed.
         *
         * R3 W3 (D-17 rev 10 (8)) — the S14 rung's own stores are ADDED:
         * cmt_blockstore, cmt_state, cmt_wal, cmt_wal_sync and cmt_light
         * (nodus_witness_v2_schema.c:1465-1517; the S14 migration's own
         * heading calls these "the four Comet stores" but the DDL there
         * creates five — cmt_light was added after that heading was
         * written, D-17 rev 5's own comment at its CREATE TABLE says so).
         * None of the five is dropped by anything past S14, so requiring
         * them raises SCHEMA_SHAPE_DRIFT exactly when it should: a
         * database that reports schema S14 but never actually ran the
         * S14 migration's table-shape verification (or ran an older
         * binary's idea of it) is not structurally what this build
         * expects. */
        static const char *const required[] = {
            "v2_blocks", "v2_domain_heads", "v2_domain_updates",
            "v2_root_history", "v2_tx_index", "v2_intent_index",
            "v2_manifests", "v2_claims_spent", "validators",
            "validator_set_snapshots", "supply_tracking",
            "cmt_blockstore", "cmt_state", "cmt_wal", "cmt_wal_sync",
            "cmt_light"
        };
        for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
            int t = pf_table_exists(w, required[i]);
            if (t < 0)      pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
            else if (t == 0) pf_add(out, NODUS_V2_PF_SCHEMA_SHAPE_DRIFT);
        }
    }

    /* The v2_*-dependent checks are SKIPPED when the tables are absent —
     * reporting a cascade of derived nonsense would bury the real issue,
     * which is already recorded as SCHEMA_SHAPE_DRIFT above.
     *
     * They are skipped, NOT returned from: an early return here would
     * also skip the unconditional Rule N gate below, which would let a
     * database that is merely un-migrated look like one with no Rule N
     * problem. (The preflight test caught exactly that.) */
    const int have_v2_blocks = (pf_table_exists(w, "v2_blocks") == 1);

    /* ── 3. GENESIS DOCUMENT: present, canonical-strict, self-consistent ─
     * R3 W3 (D-17 rev 10 (8)): a version-3 chain writes NO height-0
     * `v2_blocks` row (D-19 rev 6 withdrew the genesis block) — its
     * identity is the stored genesis DOCUMENT (D-18 rev 4/5), the
     * "genesisDoc" row in `cmt_state` under the reference's own key
     * (node/setup.go:551, NODUS_V2_GEN_GENESIS_DOC_KEY).
     *
     * Presence is probed HERE, directly against the store, so
     * GENESIS_ABSENT keeps meaning "nothing was ever written" and never
     * collides with GENESIS_MALFORMED's "something was written and it is
     * wrong" — exactly the two-way split the old height-0-row check made.
     * Only when the row is present is the canonical-strict reader
     * (`nodus_witness_v2_gen_stored_doc`) run at all: it performs its own
     * four checks (strict decode, the shared genesis content rules,
     * canonical form, and the stored `chain_id` field hashing to the
     * document — see its doc comment for why none subsumes another) and
     * collapses every one of their failures to GENESIS_MALFORMED, because
     * this preflight does not need to tell them apart — each means the
     * database's genesis identity cannot be trusted. */
    uint8_t doc_app_hash[NODUS_V2_GEN_APP_HASH_LEN];
    uint8_t doc_chain_id[NODUS_V2_GEN_CHAIN_ID_LEN];
    memset(doc_app_hash, 0, sizeof(doc_app_hash));
    memset(doc_chain_id, 0, sizeof(doc_chain_id));
    int have_genesis = 0;
    if (have_v2_blocks) {
        nodus_cmt_store_t s;
        if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK) {
            pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
        } else {
            const uint8_t *val = NULL;
            size_t vlen = 0;
            int has_row = (nodus_cmt_store_get(&s, /*state_table=*/true,
                                NODUS_V2_GEN_GENESIS_DOC_KEY, &val, &vlen)
                           == CMT_OK && val && vlen > 0);
            nodus_cmt_store_release(&s);
            if (!has_row) {
                pf_add(out, NODUS_V2_PF_GENESIS_ABSENT);
            } else {
                /* ~240 KB — NEVER a stack object (nodus_witness_v2_gen.h). */
                nodus_v2_gen_config_t *cfg = calloc(1, sizeof(*cfg));
                nodus_v2_gen_alloc_t  *allocs = NULL;
                if (!cfg) {
                    pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
                } else if (nodus_witness_v2_gen_stored_doc(w, cfg, &allocs)
                           != 0) {
                    pf_add(out, NODUS_V2_PF_GENESIS_MALFORMED);
                } else {
                    have_genesis = 1;
                    memcpy(doc_app_hash, cfg->app_hash,
                           NODUS_V2_GEN_APP_HASH_LEN);
                    memcpy(doc_chain_id, cfg->chain_id,
                           NODUS_V2_GEN_CHAIN_ID_LEN);
                }
                free(allocs);
                free(cfg);
            }
        }
    }

    /* ── 4. GENESIS MANIFEST ──────────────────────────────────────── */
    if (have_genesis) {
        /* O15A (reviewer R3): a PROBE FAULT is not "absent". Gating only
         * on `== 1` silently skipped the manifest check when the probe
         * itself failed — fail-OPEN, contradicting the discipline stated
         * at the top of this file.
         *
         * R3 W3: a version-3 derivation still writes a v2_manifests row
         * at committed_height = 0 (nodus_witness_v2_gen_derive_v3's own
         * step order — the manifest precedes the Comet genesis apply), so
         * this check is UNCHANGED by the flip. */
        int mt = pf_table_exists(w, "v2_manifests");
        if (mt < 0) {
            pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
        } else if (mt == 0) {
            pf_add(out, NODUS_V2_PF_GENESIS_MANIFEST_ABSENT);
        } else {
            sqlite3_int64 n = pf_count(w,
                "SELECT COUNT(*) FROM v2_manifests WHERE committed_height = 0");
            if (n < 0)      pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
            else if (n == 0) pf_add(out, NODUS_V2_PF_GENESIS_MANIFEST_ABSENT);
        }
    }

    /* ── 5. GENESIS SELF-CONSISTENCY: app_hash vs the ledger's IDENTITY ─
     * R3 W3 (D-17 rev 10 (8)): the document's `app_hash` field (D-19 rev 6
     * (1): AppHash carries the ledger's global state root) must equal the
     * app hash the chain actually STARTED FROM. Before this delta that
     * comparison target was `nodus_witness_v2_committed_global_root(w)` —
     * the CURRENT committed global root — unconditionally. That is wrong
     * past height 0: at the time this was measured, this ledger's global
     * root changed at EVERY block (Rule N attendance wrote the proposer's
     * `last_signed_block` into the validators leaf,
     * nodus_witness_v2_record_attendance, called from
     * nodus_witness_v2_apply_block — BOTH retired by tokenomics-v3 P1,
     * which relocated attendance out-of-root into `v2_attendance` and
     * moves the root only at the epoch boundary's digest leg; ANY
     * transaction in a block still moves it, which is why this height-
     * aware fix remains needed), so from height 1 on the CURRENT
     * root is no longer the GENESIS one and the comparison raised issue
     * 17 on every healthy node past its first block — measured on the
     * Genesis Protocol harness at production constants (evidence kept at
     * /tmp/stagef-20260917T012620Z): every fleet node refused every
     * `w_v2_gbundle_q` once it had committed past height 0, because
     * `nodus_witness_v2_gate_state` re-runs this whole preflight on every
     * request and NOT_READY never clears.
     *
     * HEIGHT-AWARE FIX: at tip < 1 (no committed block — `v2_blocks` is
     * empty) the genesis root has not yet been superseded by anything,
     * so the ORIGINAL comparison — `doc_app_hash` vs the RECOMPOSED
     * committed root, exactly as `nodus_witness_v2_genesis_cmt` composed
     * it from the committed DomainHeads — still holds and is unchanged.
     * At tip >= 1 the ledger has moved on, so the comparison target
     * becomes BLOCK 1's header AppHash instead, read from the Comet
     * blockstore (`nodus_cmt_bs_load_block_meta`, height 1,
     * `meta.header.app_hash` / `.app_hash_len`,
     * cmt_pb_block_meta_t.header : cmt_pb_header_t, field 11,
     * shared/dnac/cmt_pb.h:256-271 — CMT_PB_HASH_MAX is 64,
     * shared/dnac/cmt_pb.h:129, matching NODUS_V2_GEN_APP_HASH_LEN).
     * This is the SAME identity check 5 has always wanted, just read at
     * a height where it is still answerable: cometbft @709fd12b
     * `state/state.go` `MakeGenesisState` sets `state.AppHash =
     * genDoc.AppHash` and `state/validation.go` `validateBlock` requires
     * `block.AppHash == state.AppHash` for every block including the
     * first, so block 1's header AppHash IS the genesis app hash,
     * certified by +2/3 of the committee that decided block 1 — the
     * genesis app_hash never stops being recorded, it just moves from
     * "the current root" (only true at height 0) to "block 1's header"
     * (true at every height from then on, since block headers are
     * immutable once decided).
     *
     * A missing or undecodable block-1 meta at tip >= 1 is
     * INSPECTION_FAULT — a chain that has moved past genesis MUST be
     * able to answer this, so an inability to is a probe fault, never a
     * silent skip. A genuine mismatch is still issue 17 — its MEANING is
     * unchanged ("the document's app_hash is not the app hash the ledger
     * started from"), only the READING of "what the ledger started from"
     * is now height-aware. */
    if (have_genesis) {
        sqlite3_int64 n_blocks = pf_count(w, "SELECT COUNT(*) FROM v2_blocks");
        if (n_blocks < 0) {
            pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
        } else if (n_blocks == 0) {
            uint8_t committed_root[64];
            if (nodus_witness_v2_committed_global_root(w, committed_root)
                != 0) {
                pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
            } else if (memcmp(doc_app_hash, committed_root, 64) != 0) {
                pf_add(out, NODUS_V2_PF_GENESIS_APP_HASH_MISMATCH);
            }
        } else {
            nodus_cmt_store_t s;
            if (nodus_cmt_store_init(&s, w->db, false) != CMT_OK) {
                pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
            } else {
                nodus_cmt_block_meta_t meta;
                bool found = false;
                memset(&meta, 0, sizeof(meta));
                if (nodus_cmt_bs_load_block_meta(&s, 1, &meta, &found)
                        != CMT_OK || !found) {
                    pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
                } else if (meta.header.app_hash_len != 64 ||
                           memcmp(doc_app_hash, meta.header.app_hash, 64)
                               != 0) {
                    pf_add(out, NODUS_V2_PF_GENESIS_APP_HASH_MISMATCH);
                }
                nodus_cmt_store_release(&s);
            }
        }
    }

    /* ── 6. CHAIN ID: derived vs the one this handle is running under ─
     * The handle's chain id is installed from the database FILENAME on
     * the restart path. Committed state is the authority; a disagreement
     * means two authorities exist, which is precisely what must not be
     * activated.
     *
     * R3 W3: `derived` is the stored document's own `chain_id` field,
     * already proved to hash to the document by check 3 above — no
     * second decode of the ~56 KB document is needed. CHAIN_ID_UNRESOLVABLE
     * is RETIRED (see its doc comment): under the canonical-strict reader
     * there is no longer a distinguishable "present, well-shaped, but
     * unresolvable" state. */
    if (have_genesis) {
        /* The canonical chain id is 16 bytes; the handle stores 32
         * with the upper half zeroed (nodus_witness_set_chain_id). */
        if (memcmp(doc_chain_id, w->chain_id, 16) != 0)
            pf_add(out, NODUS_V2_PF_CHAIN_ID_DISAGREEMENT);
    }

    /* ── 7. VALIDATOR AUTHORITY for epoch 0 ───────────────────────── */
    if (have_v2_blocks) {
        dna_vset_snapshot_t *snap = NULL;
        uint32_t n = 0, q = 0;
        int arc = nodus_witness_v2_epoch_authority_for_epoch(w, 0, &snap,
                                                             &n, &q);
        if (arc > 0) {
            pf_add(out, NODUS_V2_PF_VSET_SNAPSHOT_ABSENT);
        } else if (arc < 0) {
            pf_add(out, NODUS_V2_PF_VSET_SNAPSHOT_INVALID);
        } else if (!snap || n == 0) {
            pf_add(out, NODUS_V2_PF_VSET_SNAPSHOT_INVALID);
        }
        dna_vset_free(&snap);
    }

    /* ── 8. SUPPLY CONSERVATION over committed state ──────────────── */
    if (have_v2_blocks && nodus_witness_v2_supply_check(w) != 0)
        pf_add(out, NODUS_V2_PF_SUPPLY_INCONSISTENT);

    /* ── 9. RULE N — obligation DISCHARGED (O15C, rewritten P1) ───────
     * O15A raised issue 12 UNCONDITIONALLY because this build had no V2
     * attendance source. O15C supplied one (proposer-credit); operator O4
     * (2026-09-23, tokenomics-v3 P1) replaced it with REAL signature
     * attendance: the apply engine credits every COMMIT-flagged vote of
     * cometbft's `decided_last_commit` inside the one block transaction,
     * before any root computation (`nodus_witness_v2_attendance_credit`,
     * called from nodus_witness_v2_apply.c), and the V2 epoch boundary
     * evaluates every ACTIVE row against the two-predicate liveness bar
     * (nodus_witness_v2_epoch.c `v2ep_rule_n` — no base-leader blame).
     * With the writer present in this build, the standing issue's own
     * removal condition ("removed when the live-integration season
     * supplies the writer") is met: the check is DELETED, the id is
     * retired, never reused.
     *
     * ── 9b. O15C — committed activation authority sanity ─────────────
     * DELETED by O15J Faz 3, with the ceremony it guarded. It raised
     * issue 15 for a committed activation record this binary could not
     * interpret and issue 16 for one naming a target this binary was not
     * running. There is no activation record any more — no table stores
     * one, no transaction writes one and no build reads one — so the
     * check has nothing to consult. Both ids are RETIRED, never reused
     * (nodus_witness_v2_preflight.h). */

    /* ── 10. INGRESS must not be reachable ────────────────────────────
     *
     * O15A left this issue DECLARED BUT NEVER RAISED, and said so: ingress
     * was closed STRUCTURALLY, because no protocol/server/client/transport
     * translation unit referenced any Ledger V2 identity object, so there
     * was nothing to compute and no switch to read.
     *
     * O15B RETIRED THAT ARGUMENT BY WRITING THE INGRESS CODE. The V2 wire
     * codec, the ingress adapter and the sync path now exist and are
     * linked, so "no wire message can express a v3 block" is no longer
     * true, and an issue that merely asserts the old reasoning would be
     * reporting a fact that expired.
     *
     * So it is now COMPUTED, from what this node is ACTUALLY DOING:
     * `nodus_witness_v2_ingress_is_armed()` — the runtime flag that is the
     * sole thing making a V2 frame dispatchable, and which
     * `nodus_witness_v2_ingress_arm()` refuses to set unless the
     * activation gate is OPEN.
     *
     * Note carefully what is NOT the condition: COMPILING the ingress code
     * does not count as enabled ingress, and neither does linking it. If
     * it did, this issue would fire on every node from this season onward
     * and would say nothing. The condition is reachability at run time.
     *
     * The issue is raised when ingress is reachable while the gate is not
     * OPEN — the state that must never occur, and the one a future build
     * could reach by arming without authority. Reachability WITH an open
     * gate is the activated configuration and is not an issue; it is also
     * unreachable in this build, because the gate can never open.
     */
    /* NON-RECURSIVE BY CONSTRUCTION. The gate is (authority AND preflight
     * readiness), and we ARE the readiness half — calling
     * nodus_witness_v2_gate_state() here would call straight back into this
     * function and never terminate. So the "would the gate be open?"
     * condition is assembled locally from its two independent parts:
     *
     *   authority : nodus_witness_v2_gate_authority_present() — the half
     *               that does not consult the preflight, exposed for
     *               exactly this reason.
     *   readiness : `out->n_issues == 0` RIGHT HERE. This check is the
     *               LAST one in the function, so every other issue has
     *               already been recorded; an empty list at this point is
     *               precisely what `ready` will be set to two lines below.
     *
     * Placing this check last is therefore load-bearing, not cosmetic. */
    if (nodus_witness_v2_ingress_is_armed(w)) {
        int would_open = nodus_witness_v2_gate_authority_present(w) &&
                         (out->n_issues == 0);
        if (!would_open) {
            QGP_LOG_ERROR(LOG_TAG, "%s",
                          "V2 ingress is ARMED while the activation gate is "
                          "not OPEN — activation must not proceed");
            pf_add(out, NODUS_V2_PF_INGRESS_ENABLED);
        }
    }

    out->ready = (out->n_issues == 0);
    return 0;
}
