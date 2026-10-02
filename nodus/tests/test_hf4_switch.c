/**
 * @file nodus/tests/test_hf4_switch.c
 * @brief HF-4 part A1 — the rule-set generation SWITCH (engine phase
 *        6b'), its registry transform KAT, the per-item single-use fact,
 *        and the replay invariance of a refused param-9 leg.
 *
 * Design docs/plans/2026-10-02-onchain-names-design.md rev 4 §1.2-§1.4,
 * §3; decision docs/plans/decisions/2026-10-02-onchain-names.md.
 *
 * ── WHAT IT PROVES ──────────────────────────────────────────────────────
 *  A. KAT — the pure transforms (nodus_witness_domreg_gen_manifest /
 *     _gen_record) over FIXED input bytes (spelled out at the KAT
 *     below): every copied field is copied, the four replaced fields come
 *     from compiled generation 2; the post-switch manifest hashes and the
 *     domreg_root over the two post records equal INDEPENDENT-oracle
 *     literals, keyed to DNAC_RULESET_SWITCH_SPEC_VERSION 1 (a static
 *     assert: changing the switch fails to compile here until the version
 *     — and with it D2 — is bumped and the KAT re-derived). Refusals: a
 *     manifest not at generation 1 (1), a domain mismatch (-1), a record
 *     that is not ACTIVE or carries a pending / proposal / schedule (-1).
 *  B. ENGINE, production runtimes, param 7 (HF-2) effective 1 and param 9
 *     (D2) effective H = 4 committed at genesis, idle blocks: blocks 1-2
 *     leave the registry at generation 1; block 3 (= H-1) switches —
 *     SYSTEM v7 / CORE v5 with the compiled generation-2 hashes and type
 *     lists, every other manifest and record field unchanged, the record
 *     hash recomputed; BOTH domains touched (a DomainUpdate each at
 *     height 3, CORE's with pre_root == post_root, SYSTEM's moved); heads
 *     and root-history rows name generation 2; the domreg root moved; the
 *     committed global root equals a fresh recomputation; the registry
 *     now resolves the generation-2 runtimes. Block 4 (= H, idle) applies
 *     under generation 2 and does NOT switch again; the registry is
 *     byte-unchanged by it (edge trigger, single switch).
 *  C. ENGINE FAULT — the vote reaches its edge while the registry is not
 *     generation 1 (rewritten by hand after block 2): block 3 is a node
 *     FAULT ("registry is not generation 1"), the whole DB byte-unchanged.
 *  D. ENGINE, per-item ctx fact — two param-9 legs in ONE block (a probe
 *     SYSTEM exec forwards to the real nodus_rt_system_exec with a quorum
 *     verdict and records ctx.ruleset_gen2_voted): the first item sees 0
 *     and applies, the second sees 1 — the row the first wrote in the
 *     SAME block — and is refused (code EXEC).
 *  E. ENGINE, replay invariance — a param-14 leg (refused by the scalar
 *     rules' range gate: the exact path a param-9 leg took on the pre-
 *     HF-4 build, where 9 > MAX_ID), a param-9 leg with a wrong value
 *     (scalar refusal under HF-4) and a param-9 leg refused by a stateful
 *     rule (epoch-boundary H-1) are all code EXEC with the SAME gas_wanted
 *     and gas_used: the HF-4 rules added no read and no charge to a
 *     refused CHAIN_CONFIG leg, so an old block's results hash replays
 *     unchanged.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build; the effective heights are
 * derived from DNAC_EPOCH_LENGTH / DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_
 * BLOCKS as compiled. Environment: none.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One /tmp/test_hf4_switch_XXXXXX directory per case, removed at its end
 * (left behind when a CHECK aborts).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  - Until the ORCHESTRATOR fills the HF4-ORACLE literals (A's three KAT
 *    values here; the generation-2 pins in nodus_witness_runtime.c; D2 in
 *    dnac.h), A fails, and B/C fail at the first block judged under
 *    generation 2 (an all-zero policy digest is a block-context FAULT).
 *  - B pins the fixture's H-1 roots by SELF-CONSISTENCY (committed ==
 *    recomputed, moved / unmoved) — not by an oracle literal: the
 *    fixture's full state is not oracle-computable. The oracle pins the
 *    registry transform (A), which is what the switch changes.
 *  - D and E fabricate the committee verdict inside the probe (quorum
 *    met) because the fixture's validators have no secret keys; the auth
 *    hook itself still verifies the real submitter signature. E's
 *    "pre-HF-4 path" is a stand-in (param 14 through the same range
 *    gate), not a replay of a block committed by the base binary.
 *  - The "unreadable param-9 history → FAULT" branch of 6b' and of the
 *    ctx fill is not induced here (no fault-injection hook reaches the
 *    chain_config read).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_roots_v2.h"
#include "witness/nodus_witness_runtime.h"
#include "nodus/nodus_chain_config.h"

#include "dnac/dnac.h"
#include "dnac/domain_wire.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "v2_genesis_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg)); \
        return 1; \
    } \
    g_checks++; \
} while (0)

static int g_checks = 0;

#define E_LEN   ((uint64_t)DNAC_EPOCH_LENGTH)
#define GRACE_E ((uint64_t)DNAC_CHAIN_CONFIG_GRACE_ERGONOMIC_BLOCKS)
#define D2      ((uint64_t)DNAC_CFG_RULESET_GEN2_D2)

/* The KAT below is the expectation of switch spec version 1. */
_Static_assert(DNAC_RULESET_SWITCH_SPEC_VERSION == 1u,
               "the switch changed: bump the KAT with the version");

/* ══ A. KAT literals — INDEPENDENT oracle (never this build's encoder) ══
 *
 * INPUT (both manifests DomainManifest v1, fee_policy 1, quotas 0,
 * upgrade_authority 1, activation_epoch 0, readiness_policy 1):
 *   SYSTEM: domain 0, name "SYSTEM", kind 1, abi 1, ruleset_version 6,
 *           ruleset_hash = generation-1 SYSTEM pin (ca05b4d9…efa3),
 *           genesis_state_root = 64 × 0x11, tx_types {4,5,6,7,9,10};
 *   CORE:   domain 1, name "DNA_CORE", kind 1, abi 1, ruleset_version 4,
 *           ruleset_hash = generation-1 CORE pin (b87aabb8…8852),
 *           genesis_state_root = 64 × 0x22, tx_types {1,2,3,11,12,13};
 *   records: record_version 1, status ACTIVE (3), current_manifest_hash
 *           = DOMMAN hash of the input manifest, every other field 0.
 * OUTPUT pinned: the DOMMAN hash of each post-switch manifest (the
 * generation-2 version + hash + type list replaced, every other field
 * copied), and the registry root ("NDS.DRLEAF.v1" / "NDS.DRNODE.v1") over
 * the two post-switch records (each = its input with the new manifest
 * hash). */
/* K1-K3 of shared/dnac/tests/hf4_switch_oracle.py (independent python;
 * its control leg reproduced test_domain_wire.c's shipped manifest, leaf
 * and 1/2/3-record root KATs first; written without reading this C). */
static const uint8_t HF4_KAT_SYS_MANIFEST_HASH_POST[64] = {
    0xd2, 0x59, 0x85, 0xb6, 0x00, 0x52, 0xba, 0x01,
    0x63, 0x5b, 0xc5, 0x40, 0xab, 0x9b, 0x8e, 0x30,
    0xf8, 0x2e, 0x52, 0x3a, 0xba, 0x02, 0x98, 0x07,
    0xbe, 0x6a, 0x0f, 0xd7, 0xd9, 0xf9, 0xc9, 0x6c,
    0x2e, 0x6f, 0x29, 0xf7, 0xb3, 0x51, 0xd0, 0xfe,
    0xb8, 0xb1, 0xc2, 0x87, 0xe7, 0xc3, 0x8d, 0x64,
    0x0a, 0x31, 0x10, 0xa0, 0xe9, 0x5a, 0xd5, 0x2d,
    0x61, 0xe2, 0x47, 0xe5, 0x46, 0xb3, 0x80, 0x74
};
static const uint8_t HF4_KAT_CORE_MANIFEST_HASH_POST[64] = {
    0x9a, 0xe3, 0x43, 0x91, 0x2c, 0x8e, 0xc5, 0xc7,
    0x92, 0x64, 0x86, 0x85, 0x0e, 0x45, 0x49, 0x84,
    0xd2, 0x96, 0xa1, 0x0a, 0x0d, 0x86, 0x7a, 0xa4,
    0xac, 0x49, 0x9a, 0xc1, 0xbd, 0xaf, 0xf1, 0x80,
    0xc3, 0x23, 0x7b, 0xcc, 0xc6, 0x88, 0xa2, 0xb0,
    0xb5, 0x45, 0x9f, 0x01, 0xb6, 0x7a, 0x9f, 0x81,
    0xb3, 0xa5, 0xb7, 0x0f, 0x01, 0x9d, 0x5b, 0x48,
    0x31, 0x80, 0x53, 0x45, 0x2c, 0xa6, 0xec, 0xeb
};
static const uint8_t HF4_KAT_DOMREG_ROOT_POST[64] = {
    0x13, 0xab, 0x83, 0x3e, 0x02, 0xf3, 0xa7, 0xf8,
    0xb7, 0x1d, 0x29, 0xcf, 0xa6, 0x31, 0x5c, 0x39,
    0xdf, 0x73, 0xdd, 0x20, 0xbd, 0xb2, 0xd5, 0x7d,
    0x6c, 0x88, 0x35, 0x0f, 0x81, 0xfd, 0x35, 0x52,
    0xe0, 0x57, 0x8e, 0x87, 0x92, 0x01, 0xcf, 0x9f,
    0xda, 0x72, 0xe3, 0x78, 0xa6, 0x94, 0xa2, 0xdf,
    0x97, 0x7e, 0x61, 0x22, 0xfc, 0x2d, 0x73, 0x20,
    0xcf, 0x25, 0x13, 0xd8, 0x77, 0xd7, 0x37, 0x7f
};

static void kat_manifest(dna_domain_manifest_t *m,
                         const nodus_domain_runtime_t *g1, uint8_t fill) {
    memset(m, 0, sizeof(*m));
    m->manifest_version = DNA_DOMMAN_VERSION;
    m->domain_id = g1->domain_id;
    memcpy(m->name, g1->descriptor.name, DNA_DOM_NAME_LEN);
    m->runtime_kind = g1->runtime_kind;
    m->runtime_abi = g1->runtime_abi;
    m->ruleset_version = g1->ruleset_version;
    memcpy(m->ruleset_hash, g1->ruleset_hash, 64);
    memset(m->genesis_state_root, fill, 64);
    m->tx_type_count = g1->descriptor.tx_type_count;
    memcpy(m->tx_types, g1->descriptor.tx_types, m->tx_type_count);
    m->fee_policy = DNA_FEEPOL_GLOBAL_BURN;
    m->upgrade_authority = DNA_UPGAUTH_CHAIN_CONFIG;
    m->readiness_policy = DNA_RDYPOL_STAGED_V1;
}

static int kat_record(dna_domreg_record_t *r, const dna_domain_manifest_t *m) {
    memset(r, 0, sizeof(*r));
    r->record_version = DNA_DOMREG_REC_VERSION;
    r->domain_id = m->domain_id;
    r->status = DNA_DOMST_ACTIVE;
    return dna_domman_hash(m, r->current_manifest_hash);
}

static int t_kat(void) {
    const nodus_domain_runtime_t *g1[2] = {
        nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_SYSTEM),
        nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_CORE) };
    const nodus_domain_runtime_t *g2[2] = {
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM),
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_CORE) };
    CHECK(g1[0] && g1[1] && g2[0] && g2[1], "compiled generations");

    dna_domain_manifest_t in[2], out[2];
    dna_domreg_record_t rin[2], rout[2];
    const uint8_t *want_mh[2] = { HF4_KAT_SYS_MANIFEST_HASH_POST,
                                  HF4_KAT_CORE_MANIFEST_HASH_POST };
    for (int k = 0; k < 2; k++) {
        kat_manifest(&in[k], g1[k], k == 0 ? 0x11 : 0x22);
        CHECK(kat_record(&rin[k], &in[k]) == 0, "input record");
        CHECK(nodus_witness_domreg_gen_manifest(&in[k], g1[k], g2[k],
                                                &out[k]) == 0,
              "manifest transform");
        /* the four REPLACED fields */
        CHECK(out[k].ruleset_version == g2[k]->ruleset_version,
              "version replaced");
        CHECK(memcmp(out[k].ruleset_hash, g2[k]->ruleset_hash, 64) == 0,
              "hash replaced");
        CHECK(out[k].tx_type_count == g2[k]->descriptor.tx_type_count &&
              memcmp(out[k].tx_types, g2[k]->descriptor.tx_types,
                     out[k].tx_type_count) == 0, "type list replaced");
        /* every other field COPIED */
        CHECK(out[k].manifest_version == in[k].manifest_version &&
              out[k].domain_id == in[k].domain_id &&
              memcmp(out[k].name, in[k].name, DNA_DOM_NAME_LEN) == 0 &&
              out[k].runtime_kind == in[k].runtime_kind &&
              out[k].runtime_abi == in[k].runtime_abi &&
              memcmp(out[k].genesis_state_root, in[k].genesis_state_root,
                     64) == 0 &&
              out[k].fee_policy == in[k].fee_policy &&
              out[k].quota_tx_per_block == in[k].quota_tx_per_block &&
              out[k].quota_verify_cost == in[k].quota_verify_cost &&
              out[k].upgrade_authority == in[k].upgrade_authority &&
              out[k].activation_epoch == in[k].activation_epoch &&
              out[k].readiness_policy == in[k].readiness_policy,
              "every other manifest field copied");
        uint8_t mh[64];
        CHECK(dna_domman_hash(&out[k], mh) == 0, "post manifest hash");
        CHECK(memcmp(mh, want_mh[k], 64) == 0,
              "post-switch manifest hash == oracle KAT");

        CHECK(nodus_witness_domreg_gen_record(&rin[k], &out[k], &rout[k])
                  == 0, "record transform");
        CHECK(memcmp(rout[k].current_manifest_hash, mh, 64) == 0,
              "record hash recomputed");
        /* every other record byte copied: the 223-byte encodings differ
         * ONLY in the 64 manifest-hash bytes at offset 9 */
        {
            uint8_t ea[DNA_DOMREG_REC_ENC_LEN], eb[DNA_DOMREG_REC_ENC_LEN];
            CHECK(dna_domreg_record_encode(&rin[k], ea) == 0 &&
                  dna_domreg_record_encode(&rout[k], eb) == 0, "encode");
            CHECK(memcmp(ea, eb, 9) == 0 &&
                  memcmp(ea + 73, eb + 73, DNA_DOMREG_REC_ENC_LEN - 73) == 0,
                  "record bytes outside the manifest hash unchanged");
            CHECK(memcmp(eb + 9, mh, 64) == 0, "hash at offset 9");
        }
    }
    {
        uint8_t root[64];
        CHECK(dna_domreg_root(rout, 2, root) == 0, "post registry root");
        CHECK(memcmp(root, HF4_KAT_DOMREG_ROOT_POST, 64) == 0,
              "post-switch registry root == oracle KAT");
    }

    /* refusals */
    {
        dna_domain_manifest_t m;
        /* a manifest already at generation 2 is NOT generation 1 */
        CHECK(nodus_witness_domreg_gen_manifest(&out[0], g1[0], g2[0], &m)
                  == 1, "a non-generation-1 manifest answers 1");
        /* hash differs, version equal: still not generation 1 */
        dna_domain_manifest_t bad = in[0];
        bad.ruleset_hash[0] ^= 1u;
        CHECK(nodus_witness_domreg_gen_manifest(&bad, g1[0], g2[0], &m)
                  == 1, "one hash bit off answers 1");
        /* SYSTEM manifest against CORE runtimes */
        CHECK(nodus_witness_domreg_gen_manifest(&in[0], g1[1], g2[1], &m)
                  == -1, "domain mismatch is -1");

        dna_domreg_record_t r = rin[0], ro;
        r.status = DNA_DOMST_PAUSED;
        CHECK(nodus_witness_domreg_gen_record(&r, &out[0], &ro) == -1,
              "a PAUSED record refuses");
        r = rin[0];
        r.proposal_present = 1;
        r.pending_present = 1;
        memset(r.proposal_digest, 0x44, 64);
        memset(r.pending_manifest_hash, 0x55, 64);
        CHECK(dna_domreg_record_validate(&r) == 0, "a valid ACTIVE "
              "record with a pending upgrade");
        CHECK(nodus_witness_domreg_gen_record(&r, &out[0], &ro) == -1,
              "a pending / proposal record refuses");
        r.scheduled_activation_epoch = E_LEN;
        r.readiness_deadline_epoch = E_LEN;
        CHECK(nodus_witness_domreg_gen_record(&r, &out[0], &ro) == -1,
              "a scheduled record refuses");
    }
    return 0;
}

/* ══ the engine fixture — a seeded version-3 chain, production runtimes ═ */

typedef struct {
    nodus_witness_t *w;
    char             dir[128];
    uint8_t          chain16[16];
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

/* HF-2 on from height 1; param 9 (value D2) effective `h9` when nonzero —
 * both committed BEFORE the engine genesis (the hf3_fx_open shape,
 * test_v2_apply.c), so no root moves after it. */
static int fx_open(fixture_t *fx, const char *tag, uint64_t h9) {
    memset(fx, 0, sizeof(*fx));
    fx->w = calloc(1, sizeof(*fx->w));
    if (!fx->w) return -1;
    snprintf(fx->dir, sizeof(fx->dir), "/tmp/test_hf4_switch_%s_XXXXXX", tag);
    if (!mkdtemp(fx->dir)) { free(fx->w); fx->w = NULL; return -1; }
    snprintf(fx->w->data_path, sizeof(fx->w->data_path), "%s", fx->dir);
    memset(fx->chain16, 0x34, sizeof(fx->chain16));
    if (v2x_seed_prepare(fx->w, fx->chain16, 0) != 0) return -1;
    if (cc_row(fx->w, DNAC_CFG_HF2_ACTIVE, DNAC_CFG_HF2_ACTIVE_ON, 1, 11)
        != 0)
        return -1;
    if (h9 && cc_row(fx->w, DNAC_CFG_RULESET_GEN2, D2, h9, 12) != 0)
        return -1;
    return v2x_seed_genesis(fx->w, fx->chain16, 0, NULL, 0, NULL);
}

static void mk_block(nodus_v2_block_t *b, uint64_t h,
                     const nodus_v2_envelope_t *envs, size_t n) {
    memset(b, 0, sizeof(*b));
    b->global_height = h;
    b->epoch = nodus_v2_epoch_for_height(h);
    b->envs = envs;
    b->n_envs = n;
}

/* the registry's (record, manifest) of one domain */
static int reg_get(nodus_witness_t *w, uint32_t dom, dna_domreg_record_t *r,
                   dna_domain_manifest_t *m) {
    return nodus_witness_domreg_get(w, dom, r, m, NULL);
}

/* a whole-row snapshot of the registry (record + manifest bytes) */
static int reg_digest(nodus_witness_t *w, uint8_t out[64]) {
    uint8_t root[64];
    return nodus_witness_domreg_root(w, root) == 0
               ? (memcpy(out, root, 64), 0) : -1;
}

static int head_rv(nodus_witness_t *w, uint32_t dom, uint32_t *rv,
                   uint64_t *dh) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT head, domain_height FROM "
                           "v2_domain_heads WHERE domain_id = ?1", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 0) == DNA_V2_DOMHEAD_ENC_LEN) {
        const uint8_t *h = sqlite3_column_blob(st, 0);
        *rv = ((uint32_t)h[84] << 24) | ((uint32_t)h[85] << 16) |
              ((uint32_t)h[86] << 8) | h[87];   /* id4 root64 h8 lu8 rv4 */
        *dh = (uint64_t)sqlite3_column_int64(st, 1);
        ok = 0;
    }
    sqlite3_finalize(st);
    return ok;
}

static int upd_at(nodus_witness_t *w, uint64_t gh, uint32_t dom,
                  dna_domain_update_t *u) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT upd FROM v2_domain_updates WHERE "
                           "global_height = ?1 AND domain_id = ?2", -1, &st,
                           NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)gh);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        dna_dupd_decode(sqlite3_column_blob(st, 0),
                        (size_t)sqlite3_column_bytes(st, 0), u) == 0)
        ok = 0;
    sqlite3_finalize(st);
    return ok;
}

static int hist_at(nodus_witness_t *w, uint64_t gh, uint32_t dom,
                   uint32_t *rv, uint8_t rh[64]) {
    sqlite3_stmt *st = NULL;
    int ok = -1;
    if (sqlite3_prepare_v2(w->db, "SELECT ruleset_version, ruleset_hash "
                           "FROM v2_root_history WHERE global_height = ?1 "
                           "AND domain_id = ?2", -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)gh);
    sqlite3_bind_int64(st, 2, (sqlite3_int64)dom);
    if (sqlite3_step(st) == SQLITE_ROW &&
        sqlite3_column_bytes(st, 1) == 64) {
        *rv = (uint32_t)sqlite3_column_int64(st, 0);
        memcpy(rh, sqlite3_column_blob(st, 1), 64);
        ok = 0;
    }
    sqlite3_finalize(st);
    return ok;
}

static int count_q(nodus_witness_t *w, const char *sql, sqlite3_int64 *n) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(w->db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) *n = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

/* ══ B. the switch at H-1, H = 4 ═══════════════════════════════════ */

static int t_switch(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    const uint64_t H = 4;
    const nodus_domain_runtime_t *g1s =
        nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *g1c =
        nodus_runtime_for_generation(NODUS_RT_GEN_1, DNA_DOMAIN_CORE);
    const nodus_domain_runtime_t *g2s =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_SYSTEM);
    const nodus_domain_runtime_t *g2c =
        nodus_runtime_for_generation(NODUS_RT_GEN_2, DNA_DOMAIN_CORE);
    CHECK(g1s && g1c && g2s && g2c, "compiled generations");
    CHECK((H - 1u) % E_LEN != 0, "H-1 is not a boundary in this build");

    CHECK(fx_open(&fx, "edge", H) == 0, "seeded chain (HF-2 on, vote at 4)");

    dna_domreg_record_t r0s, r0c;
    dna_domain_manifest_t m0s, m0c;
    CHECK(reg_get(fx.w, DNA_DOMAIN_SYSTEM, &r0s, &m0s) == 0 &&
          reg_get(fx.w, DNA_DOMAIN_CORE, &r0c, &m0c) == 0, "registry");
    CHECK(m0s.ruleset_version == g1s->ruleset_version &&
          m0c.ruleset_version == g1c->ruleset_version,
          "genesis registry is generation 1");

    /* blocks 1 and 2: not the edge — the registry does not move */
    uint8_t dr0[64], dr[64];
    CHECK(reg_digest(fx.w, dr0) == 0, "registry root at genesis");
    for (uint64_t h = 1; h <= 2; h++) {
        mk_block(&b, h, NULL, 0);
        CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "idle block before H-1");
        CHECK(reg_digest(fx.w, dr) == 0 && memcmp(dr, dr0, 64) == 0,
              "no switch before H-1");
    }
    uint32_t rv = 0;
    uint64_t dh_s0 = 0, dh_c0 = 0;
    CHECK(head_rv(fx.w, DNA_DOMAIN_SYSTEM, &rv, &dh_s0) == 0 &&
          rv == g1s->ruleset_version, "SYSTEM head at generation 1");
    CHECK(head_rv(fx.w, DNA_DOMAIN_CORE, &rv, &dh_c0) == 0 &&
          rv == g1c->ruleset_version, "CORE head at generation 1");

    /* block 3 = H-1: THE SWITCH */
    mk_block(&b, H - 1u, NULL, 0);
    CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "the H-1 block commits");

    dna_domreg_record_t r1s, r1c;
    dna_domain_manifest_t m1s, m1c;
    CHECK(reg_get(fx.w, DNA_DOMAIN_SYSTEM, &r1s, &m1s) == 0 &&
          reg_get(fx.w, DNA_DOMAIN_CORE, &r1c, &m1c) == 0, "registry after");
    {
        dna_domain_manifest_t es, ec;
        dna_domreg_record_t ers, erc;
        CHECK(nodus_witness_domreg_gen_manifest(&m0s, g1s, g2s, &es) == 0 &&
              nodus_witness_domreg_gen_manifest(&m0c, g1c, g2c, &ec) == 0,
              "expected manifests");
        /* canonical bytes, never struct memory (padding) */
        uint8_t h1[64], h2[64];
        CHECK(dna_domman_hash(&m1s, h1) == 0 && dna_domman_hash(&es, h2) == 0
              && memcmp(h1, h2, 64) == 0,
              "committed SYSTEM manifest == the transform of genesis'");
        CHECK(dna_domman_hash(&m1c, h1) == 0 && dna_domman_hash(&ec, h2) == 0
              && memcmp(h1, h2, 64) == 0,
              "committed CORE manifest == the transform of genesis'");
        CHECK(nodus_witness_domreg_gen_record(&r0s, &es, &ers) == 0 &&
              nodus_witness_domreg_gen_record(&r0c, &ec, &erc) == 0,
              "expected records");
        uint8_t a[DNA_DOMREG_REC_ENC_LEN], c[DNA_DOMREG_REC_ENC_LEN];
        CHECK(dna_domreg_record_encode(&r1s, a) == 0 &&
              dna_domreg_record_encode(&ers, c) == 0 &&
              memcmp(a, c, sizeof(a)) == 0, "SYSTEM record bytes");
        CHECK(dna_domreg_record_encode(&r1c, a) == 0 &&
              dna_domreg_record_encode(&erc, c) == 0 &&
              memcmp(a, c, sizeof(a)) == 0, "CORE record bytes");
    }
    CHECK(m1s.ruleset_version == 7 && m1c.ruleset_version == 5,
          "SYSTEM v7 / CORE v5");
    CHECK(memcmp(m1s.ruleset_hash, g2s->ruleset_hash, 64) == 0 &&
          memcmp(m1c.ruleset_hash, g2c->ruleset_hash, 64) == 0,
          "generation-2 hashes");
    CHECK(reg_digest(fx.w, dr) == 0 && memcmp(dr, dr0, 64) != 0,
          "the registry root moved");
    {
        const nodus_domain_runtime_t *rs = NULL, *rc = NULL;
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_SYSTEM, 1, &rs)
                  == 0 && rs == g2s, "SYSTEM resolves generation 2");
        CHECK(nodus_witness_v2_runtime_for(fx.w, DNA_DOMAIN_CORE, 1, &rc)
                  == 0 && rc == g2c, "CORE resolves generation 2");
    }
    /* both touched: one DomainUpdate each at H-1, heads advanced */
    {
        dna_domain_update_t us, uc;
        CHECK(upd_at(fx.w, H - 1u, DNA_DOMAIN_SYSTEM, &us) == 0 &&
              upd_at(fx.w, H - 1u, DNA_DOMAIN_CORE, &uc) == 0,
              "a DomainUpdate for BOTH domains at H-1");
        CHECK(memcmp(us.pre_root, us.post_root, 64) != 0,
              "SYSTEM's root moved (domreg_root is a SYSTEM leg)");
        CHECK(memcmp(uc.pre_root, uc.post_root, 64) == 0,
              "CORE's root did not move (accepted: HF-2 is on)");
        CHECK(us.ruleset_version == 7 && uc.ruleset_version == 5,
              "the H-1 updates name generation 2 (design §1.3)");
        CHECK(us.res_tx_count == 0 && uc.res_tx_count == 0,
              "no item carried them");
        uint64_t dh = 0;
        CHECK(head_rv(fx.w, DNA_DOMAIN_SYSTEM, &rv, &dh) == 0 &&
              rv == 7 && dh == dh_s0 + 1u, "SYSTEM head: v7, advanced");
        CHECK(head_rv(fx.w, DNA_DOMAIN_CORE, &rv, &dh) == 0 &&
              rv == 5 && dh == dh_c0 + 1u, "CORE head: v5, advanced");
        uint8_t rh[64];
        CHECK(hist_at(fx.w, H - 1u, DNA_DOMAIN_SYSTEM, &rv, rh) == 0 &&
              rv == 7 && memcmp(rh, g2s->ruleset_hash, 64) == 0,
              "SYSTEM root history names generation 2");
        CHECK(hist_at(fx.w, H - 1u, DNA_DOMAIN_CORE, &rv, rh) == 0 &&
              rv == 5 && memcmp(rh, g2c->ruleset_hash, 64) == 0,
              "CORE root history names generation 2");
    }
    /* the committed H-1 roots equal a fresh recomputation */
    {
        uint8_t committed[64], fresh[64];
        CHECK(nodus_witness_v2_committed_global_root(fx.w, committed) == 0,
              "committed global root");
        CHECK(nodus_witness_global_root_v2(fx.w, fresh, NULL, NULL, NULL)
                  == 0, "recomputed global root");
        CHECK(memcmp(committed, fresh, 64) == 0,
              "committed H-1 global root == recomputation");
    }

    /* block 4 = H, idle, under generation 2: no second switch */
    {
        uint8_t before[64];
        sqlite3_int64 n_upd = -1;
        CHECK(reg_digest(fx.w, before) == 0, "registry before H");
        mk_block(&b, H, NULL, 0);
        CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0,
              "the idle H block applies under generation 2");
        CHECK(reg_digest(fx.w, dr) == 0 && memcmp(dr, before, 64) == 0,
              "no second switch (edge trigger)");
        CHECK(count_q(fx.w, "SELECT COUNT(*) FROM v2_domain_updates WHERE "
                      "global_height = 4", &n_upd) == 0 && n_upd == 0,
              "the idle H block touches nothing");
    }
    fx_close(&fx);
    return 0;
}

/* ══ C. the edge with a registry that is not generation 1 → FAULT ══ */

static int t_switch_not_gen1_faults(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    CHECK(fx_open(&fx, "notg1", 4) == 0, "seeded chain (vote at 4)");
    for (uint64_t h = 1; h <= 2; h++) {
        mk_block(&b, h, NULL, 0);
        CHECK(v2x_cmt_apply_ok(fx.w, &b) == 0, "idle block");
    }
    /* the registry is rewritten to generation 2 OUTSIDE any block */
    CHECK(sqlite3_exec(fx.w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
              == SQLITE_OK, "begin");
    CHECK(nodus_witness_domreg_generation_switch(fx.w, NODUS_RT_GEN_1,
                                                 NODUS_RT_GEN_2) == 0,
          "hand switch");
    CHECK(sqlite3_exec(fx.w->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK,
          "commit");
    /* the transform refuses a registry that is not at its source */
    CHECK(sqlite3_exec(fx.w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
              == SQLITE_OK, "begin");
    CHECK(nodus_witness_domreg_generation_switch(fx.w, NODUS_RT_GEN_1,
                                                 NODUS_RT_GEN_2) == 1,
          "a second switch answers 'not generation 1'");
    CHECK(sqlite3_exec(fx.w->db, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK,
          "rollback");

    mk_block(&b, 3, NULL, 0);
    CHECK(v2x_cmt_fault_why(fx.w, &b, V2X_FAULT,
                            "registry is not generation 1") == 0,
          "the H-1 block is a node FAULT, DB byte-unchanged");
    fx_close(&fx);
    return 0;
}

/* ══ D/E. CHAIN_CONFIG legs through the engine ══════════════════════ */

/* The probe SYSTEM exec: record the engine-filled single-use fact, then
 * forward to the REAL hook with a quorum verdict (7 of 7 seats, power 7
 * of 7) — the fixture's validators have no secret keys. */
#define PROBE_MAX 16
static uint8_t g_seen[PROBE_MAX];
static int     g_n_seen;

static int probe_exec(const nodus_domain_runtime_t *rt,
                      const dna_env_view_t *env, uint16_t leg_index,
                      const nodus_rt_exec_ctx_t *ctx,
                      const nodus_rt_read_res_t *reads, uint16_t n_reads,
                      uint8_t *res_out, size_t res_cap, size_t *res_len_out) {
    if (!ctx || !ctx->auth) return -2;
    if (g_n_seen < PROBE_MAX) g_seen[g_n_seen++] = ctx->ruleset_gen2_voted;
    nodus_rt_auth_verdict_t av = *ctx->auth;
    av.n_approvals = 7;
    av.committee_n = 7;
    av.approved_power = 7;
    av.committee_power = 7;
    nodus_rt_exec_ctx_t c2 = *ctx;
    c2.auth = &av;
    return nodus_rt_system_exec(rt, env, leg_index, &c2, reads, n_reads,
                                res_out, res_cap, res_len_out);
}

static nodus_domain_runtime_t g_probe_table[2];

static int probe_table_install(nodus_witness_t *w) {
    size_t n = 0;
    const nodus_domain_runtime_t *g1 = nodus_runtime_builtin_table(&n);
    if (!g1 || n != 2) return -1;
    memcpy(g_probe_table, g1, sizeof(g_probe_table));
    g_probe_table[0].exec = probe_exec;
    w->v2_runtime_table = g_probe_table;
    w->v2_runtime_table_n = 2;
    g_n_seen = 0;
    return 0;
}

#define CC_CALL_LEN 41u
#define K1_AUTH_LEN (1u + NODUS_RT_AUTH_SIGNER_LEN)

typedef struct {
    uint8_t  call[CC_CALL_LEN];
    uint8_t  auth[K1_AUTH_LEN];
    uint8_t *bytes;
    size_t   len;
} cc_env_t;

static uint8_t g_pk[QGP_DSA87_PUBLICKEYBYTES], g_sk[QGP_DSA87_SECRETKEYBYTES];

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (56 - 8 * i));
}

/* One SYSTEM CHAIN_CONFIG envelope, auth_kind 1, REALLY signed by g_sk
 * over the engine-derived leg digest (two-pass: auth_len is committed,
 * the auth bytes are not). @return 0 / -1. */
static int cc_env_build(nodus_witness_t *w, uint64_t height, uint8_t param,
                        uint64_t value, uint64_t effective, uint64_t nonce,
                        cc_env_t *e) {
    dna_domain_manifest_t sys;
    memset(e, 0, sizeof(*e));
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys, NULL) != 0)
        return -1;
    e->call[0] = param;
    put64(e->call + 1, value);
    put64(e->call + 9, effective);
    put64(e->call + 17, nonce);
    put64(e->call + 25, height);                /* signed_at              */
    put64(e->call + 33, effective + 1000u);     /* valid_before           */

    dna_env_leg_in_t leg;
    memset(&leg, 0, sizeof(leg));
    leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
    leg.hdr.ruleset_version      = sys.ruleset_version;
    leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    leg.hdr.auth_kind            = NODUS_RT_AUTHKIND_DSA87_MULTI_V1;
    leg.hdr.call_len             = CC_CALL_LEN;
    leg.hdr.auth_len             = K1_AUTH_LEN;
    leg.hdr.res_max_effects      = 4;
    leg.hdr.res_max_effect_bytes = 4096;
    leg.call_data = e->call;
    leg.auth_data = e->auth;

    dna_env_in_t in;
    memset(&in, 0, sizeof(in));
    in.expiry_height       = 0;
    in.fee_amount          = 0;
    in.res_max_total_units = 200000;
    in.leg_count           = 1;
    in.legs                = &leg;

    dna_env_leg_ctx_t lctx;
    memset(&lctx, 0, sizeof(lctx));
    lctx.domain_id       = DNA_DOMAIN_SYSTEM;
    lctx.ruleset_version = sys.ruleset_version;
    memcpy(lctx.ruleset_hash, sys.ruleset_hash, 64);

    if (dna_env_encoded_size(&leg, 1, &e->len) != 0) return -1;
    e->bytes = malloc(e->len);
    if (!e->bytes) return -1;
    dna_env_preflight_t *pf = calloc(1, sizeof(*pf));
    if (!pf) return -1;
    size_t used = 0;
    int ok = -1;
    do {
        if (dna_env_encode(&in, e->bytes, e->len, &used) != 0 ||
            used != e->len) break;
        if (dna_env_preflight(e->bytes, e->len, w->v2_chain32, height,
                              &lctx, 1, pf) != DNA_ENV_PF_OK) break;
        e->auth[0] = 1;
        memcpy(e->auth + 1, g_pk, QGP_DSA87_PUBLICKEYBYTES);
        size_t sl = 0;
        if (qgp_dsa87_sign(e->auth + 1 + QGP_DSA87_PUBLICKEYBYTES, &sl,
                           pf->auth_digest[0], 64, g_sk) != 0) break;
        if (dna_env_encode(&in, e->bytes, e->len, &used) != 0 ||
            used != e->len) break;
        ok = 0;
    } while (0);
    free(pf);
    return ok;
}

static uint64_t eff_not_boundary(uint64_t floor_h) {
    uint64_t e = floor_h;
    while (((e - 1u) % E_LEN) == 0 && (e - 1u) != 0) e++;
    return e;
}

/* D — two param-9 legs in one block: the second sees the first's row */
static int t_same_block_single_use(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    cc_env_t e1, e2;
    CHECK(fx_open(&fx, "same", 0) == 0, "seeded chain (HF-2 on, no vote)");
    CHECK(probe_table_install(fx.w) == 0, "probe runtime table");

    const uint64_t h = 1;
    const uint64_t eff1 = eff_not_boundary(h + GRACE_E);
    const uint64_t eff2 = eff_not_boundary(eff1 + 3u);
    CHECK(cc_env_build(fx.w, h, DNAC_CFG_RULESET_GEN2, D2, eff1, 1, &e1)
              == 0, "first param-9 envelope");
    CHECK(cc_env_build(fx.w, h, DNAC_CFG_RULESET_GEN2, D2, eff2, 2, &e2)
              == 0, "second param-9 envelope");
    nodus_v2_envelope_t envs[2] = { { e1.bytes, e1.len },
                                    { e2.bytes, e2.len } };
    mk_block(&b, h, envs, 2);
    CHECK(v2x_cmt_apply(fx.w, &b) == 0, "the block commits");
    CHECK(b.cmt.results[0].code == NODUS_V2_TX_OK,
          "the first vote applies");
    CHECK(b.cmt.results[1].code == NODUS_V2_TX_ERR_EXEC,
          "the second vote is refused in exec");
    CHECK(g_n_seen == 2 && g_seen[0] == 0 && g_seen[1] == 1,
          "the engine re-read the single-use fact per item");
    {
        sqlite3_int64 n = -1;
        CHECK(count_q(fx.w, "SELECT COUNT(*) FROM chain_config_history "
                      "WHERE param_id = 9", &n) == 0 && n == 1,
              "exactly one param-9 row");
    }
    free(e1.bytes);
    free(e2.bytes);
    fx.w->v2_runtime_table = NULL;
    fx_close(&fx);
    return 0;
}

/* E — refused CHAIN_CONFIG legs cost the same, HF-4 rules or not */
static int t_refused_leg_gas_invariant(void) {
    fixture_t fx;
    nodus_v2_block_t b;
    cc_env_t x, y, z;
    CHECK(fx_open(&fx, "gas", 0) == 0, "seeded chain (HF-2 on, no vote)");
    CHECK(probe_table_install(fx.w) == 0, "probe runtime table");

    const uint64_t h = 1;
    const uint64_t ok_eff = eff_not_boundary(h + GRACE_E);
    const uint64_t bd_eff =
        ((h + GRACE_E - 1u) / E_LEN + 1u) * E_LEN + 1u;   /* H-1 = k·E */
    CHECK(((bd_eff - 1u) % E_LEN) == 0 && bd_eff >= h + GRACE_E,
          "a boundary effective past the grace floor");
    /* x: id 14 — the scalar range gate (the pre-HF-4 path of id 9) */
    CHECK(cc_env_build(fx.w, h, 14, 0, ok_eff, 1, &x) == 0, "param 14");
    /* y: id 9, wrong value — the HF-4 scalar rule */
    CHECK(cc_env_build(fx.w, h, DNAC_CFG_RULESET_GEN2, D2 + 1u, ok_eff, 2,
                       &y) == 0, "param 9, value D2 + 1");
    /* z: id 9, D2, H-1 an epoch boundary — an HF-4 stateful rule */
    CHECK(cc_env_build(fx.w, h, DNAC_CFG_RULESET_GEN2, D2, bd_eff, 3, &z)
              == 0, "param 9, boundary effective");
    CHECK(x.len == y.len && y.len == z.len, "same envelope size");

    nodus_v2_envelope_t envs[3] = { { x.bytes, x.len }, { y.bytes, y.len },
                                    { z.bytes, z.len } };
    mk_block(&b, h, envs, 3);
    CHECK(v2x_cmt_apply(fx.w, &b) == 0, "the block commits");
    for (int i = 0; i < 3; i++)
        CHECK(b.cmt.results[i].code == NODUS_V2_TX_ERR_EXEC,
              "every leg refused in exec");
    CHECK(b.cmt.results[0].gas_used == b.cmt.results[1].gas_used &&
          b.cmt.results[1].gas_used == b.cmt.results[2].gas_used,
          "the same gas_used: no read, no charge was added");
    CHECK(b.cmt.results[0].gas_wanted == b.cmt.results[1].gas_wanted &&
          b.cmt.results[1].gas_wanted == b.cmt.results[2].gas_wanted,
          "the same gas_wanted");
    free(x.bytes);
    free(y.bytes);
    free(z.bytes);
    fx.w->v2_runtime_table = NULL;
    fx_close(&fx);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "kat_registry_transform",   t_kat },
        { "switch_at_h_minus_1",      t_switch },
        { "switch_not_gen1_faults",   t_switch_not_gen1_faults },
        { "same_block_single_use",    t_same_block_single_use },
        { "refused_leg_gas_invariant", t_refused_leg_gas_invariant },
    };
    size_t failed = 0, n = sizeof(cases) / sizeof(cases[0]);
    {
        uint8_t seed[32];
        memset(seed, 0x4F, sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk, g_sk, seed) != 0) {
            fprintf(stderr, "test_hf4_switch: key generation failed\n");
            return 1;
        }
    }
    for (size_t i = 0; i < n; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-28s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_hf4_switch: %zu/%zu cases passed, %d checks\n",
            n - failed, n, g_checks);
    return failed ? 1 : 0;
}
