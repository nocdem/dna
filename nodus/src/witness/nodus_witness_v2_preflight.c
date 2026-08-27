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

#include <string.h>
#include <sqlite3.h>

#include "dnac/block_v2.h"
#include "dnac/vset_wire.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_epoch.h"
#include "witness/nodus_witness_v2_gate.h"
#include "witness/nodus_witness_v2_schema.h"
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
    /* nodus_witness_v2_gen_derive builds at S12 (canonical claim byte
     * availability); S11 (canonical envelope bytes) and S10 remain
     * accepted, each being a purely additive superset of the previous.
     * Anything else is unsupported.
     *
     * O15J Faz 3: S10 is no longer "the activation-authority chain" — its
     * two tables went with the ceremony and the rung is now a bare
     * version bump (nodus_witness_v2_schema.h). It stays accepted because
     * the ladder still passes through it and a database that stopped
     * there is still a structural superset of S9. */
    if (ver != NODUS_V2_SCHEMA_VERSION_S10 &&
        ver != NODUS_V2_SCHEMA_VERSION_S11 &&
        ver != NODUS_V2_SCHEMA_VERSION_S12)
        pf_add(out, NODUS_V2_PF_SCHEMA_UNSUPPORTED);

    /* ── 2. REQUIRED TABLES ───────────────────────────────────────── */
    {
        /* O15J Faz 3 — "v2_activation" and "v2_activation_readiness" are
         * REMOVED from this list. The activation ceremony is gone and the
         * S10 migration no longer creates them, so requiring them would
         * raise SCHEMA_SHAPE_DRIFT on every database this tree can
         * produce — making `ready` false, the gate NOT_READY and the V2
         * lane permanently unarmed. */
        static const char *const required[] = {
            "v2_blocks", "v2_domain_heads", "v2_domain_updates",
            "v2_root_history", "v2_tx_index", "v2_intent_index",
            "v2_manifests", "v2_claims_spent", "validators",
            "validator_set_snapshots", "supply_tracking"
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

    /* ── 3. GENESIS: present, well-formed, self-consistent ────────── */
    uint8_t committed_gid[64];
    int have_genesis = 0;
    if (have_v2_blocks) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT block_id, header FROM v2_blocks "
                "WHERE global_height = 0", -1, &st, NULL) != SQLITE_OK) {
            pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
        } else {
            int rc = sqlite3_step(st);
            if (rc == SQLITE_DONE) {
                pf_add(out, NODUS_V2_PF_GENESIS_ABSENT);
            } else if (rc != SQLITE_ROW) {
                pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
            } else if (sqlite3_column_bytes(st, 0) != 64 ||
                       sqlite3_column_bytes(st, 1) != DNA_BH2_ENC_SIZE) {
                pf_add(out, NODUS_V2_PF_GENESIS_MALFORMED);
            } else {
                memcpy(committed_gid, sqlite3_column_blob(st, 0), 64);
                have_genesis = 1;

                /* The stored bytes must reproduce the stored identity.
                 * This is the restart property in check form: a header
                 * that no longer hashes to its own id means the row is
                 * not the block it claims to be. */
                const uint8_t *enc = sqlite3_column_blob(st, 1);
                dna_block_header_v2_t hdr;
                if (dna_bh2_decode(enc, DNA_BH2_ENC_SIZE, &hdr) != 0) {
                    pf_add(out, NODUS_V2_PF_GENESIS_MALFORMED);
                } else if (hdr.block_height != 0) {
                    /* Filed at height 0 but claiming another height. */
                    pf_add(out, NODUS_V2_PF_GENESIS_IDENTITY_MISMATCH);
                } else {
                    /* O15A (reviewer R3): this check used to fire ONLY
                     * when block_height != 0 — i.e. never for a genuine
                     * genesis row, which is every real one. It therefore
                     * verified nothing for the row it names.
                     *
                     * A genesis identity is derived with the MANIFEST as
                     * an explicit input, so a plain re-hash legitimately
                     * differs; the correct derivation needs the committed
                     * manifest bytes, which live in this same database.
                     * Fetch them and re-derive properly. */
                    sqlite3_stmt *mq = NULL;
                    if (sqlite3_prepare_v2(w->db,
                            "SELECT manifest FROM v2_manifests "
                            "WHERE committed_height = 0 "
                            "ORDER BY manifest_seq ASC LIMIT 1",
                            -1, &mq, NULL) != SQLITE_OK) {
                        pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
                    } else {
                        if (sqlite3_step(mq) == SQLITE_ROW) {
                            const void *mb = sqlite3_column_blob(mq, 0);
                            int ml = sqlite3_column_bytes(mq, 0);
                            uint8_t gid[64];
                            if (mb && ml > 0 &&
                                dna_bh2_genesis_block_id(
                                    &hdr, (const uint8_t *)mb, (size_t)ml,
                                    gid) == 0) {
                                if (memcmp(gid, committed_gid, 64) != 0)
                                    pf_add(out,
                                        NODUS_V2_PF_GENESIS_IDENTITY_MISMATCH);
                            } else {
                                pf_add(out, NODUS_V2_PF_INSPECTION_FAULT);
                            }
                        }
                        /* No manifest row: reported by the manifest
                         * check below, not duplicated here. */
                        sqlite3_finalize(mq);
                    }
                }
            }
            sqlite3_finalize(st);
        }
    }

    /* ── 4. GENESIS MANIFEST ──────────────────────────────────────── */
    if (have_genesis) {
        /* O15A (reviewer R3): a PROBE FAULT is not "absent". Gating only
         * on `== 1` silently skipped the manifest check when the probe
         * itself failed — fail-OPEN, contradicting the discipline stated
         * at the top of this file. */
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

    /* ── 5. CHAIN ID: derived vs the one this handle is running under ─
     * The handle's chain id is installed from the database FILENAME on
     * the restart path. Committed state is the authority; a disagreement
     * means two authorities exist, which is precisely what must not be
     * activated. */
    if (have_genesis) {
        uint8_t derived[DNA_CHAIN_ID_LEN];
        if (nodus_witness_v2_chain_id(w, derived) != 0) {
            pf_add(out, NODUS_V2_PF_CHAIN_ID_UNRESOLVABLE);
        } else {
            /* The canonical chain id is 16 bytes; the handle stores 32
             * with the upper half zeroed (nodus_witness_set_chain_id). */
            if (memcmp(derived, w->chain_id, 16) != 0)
                pf_add(out, NODUS_V2_PF_CHAIN_ID_DISAGREEMENT);
        }
    }

    /* ── 6. VALIDATOR AUTHORITY for epoch 0 ───────────────────────── */
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

    /* ── 7. SUPPLY CONSERVATION over committed state ──────────────── */
    if (have_v2_blocks && nodus_witness_v2_supply_check(w) != 0)
        pf_add(out, NODUS_V2_PF_SUPPLY_INCONSISTENT);

    /* ── 8. RULE N — obligation DISCHARGED (O15C) ─────────────────────
     * O15A raised issue 12 UNCONDITIONALLY because this build had no V2
     * attendance source. O15C supplied it: the apply engine credits the
     * committed header proposer inside the one block transaction, before
     * any root computation (nodus_witness_v2_record_attendance, called
     * from nodus_witness_v2_apply.c), and the V2 epoch boundary runs the
     * transplanted leader-blame settlement (nodus_witness_v2_epoch.c —
     * the legacy bft.c:2587-2723 semantics against the committed
     * snapshot authority). With the writer present in this build, the
     * standing issue's own removal condition ("removed when the
     * live-integration season supplies the writer") is met: the check is
     * DELETED, the id is retired, never reused.
     *
     * ── 8b. O15C — committed activation authority sanity ─────────────
     * DELETED by O15J Faz 3, with the ceremony it guarded. It raised
     * issue 15 for a committed activation record this binary could not
     * interpret and issue 16 for one naming a target this binary was not
     * running. There is no activation record any more — no table stores
     * one, no transaction writes one and no build reads one — so the
     * check has nothing to consult. Both ids are RETIRED, never reused
     * (nodus_witness_v2_preflight.h). */

    /* ── 9. INGRESS must not be reachable ─────────────────────────────
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
