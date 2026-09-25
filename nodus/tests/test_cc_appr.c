/**
 * @file nodus/tests/test_cc_appr.c
 * @brief D-16 rev 7 (W4-CC) — the SYSTEM-governance approval-collection
 *        responder (`nodus_witness_handle_cc_appr_req`, verbs 40-41)
 *        driven over a REAL derived version-3 chain with 7 REAL
 *        ML-DSA-87 committee keys.
 *
 * ── WHAT THIS PROVES ────────────────────────────────────────────────────
 * That the responder signs a digest the CHAIN actually accepts: each of
 * the 7 real committee seats is asked for its approval THROUGH THE
 * RESPONDER (never a local shortcut — `nodus_witness_handle_cc_appr_req`
 * is called exactly as the T3 dispatcher would call it, over a REAL
 * connected `nodus_tcp_conn_t` so `nodus_tcp_send` writes real bytes this
 * file reads back and decodes with `nodus_t3_decode`); the assembled
 * envelope is then handed to `nodus_witness_v2_env_dry_run` — the per-item
 * dry run CheckTx calls — and it accepts. A second, INDEPENDENT
 * recomputation of the "DNA.CCSET.v1" set hash and the "DNA.CCAPPR.v1"
 * approval digest (this file's own preimage bytes, not
 * `nodus_rt_committee_set_hash`/`nodus_rt_cc_approval_digest`) is checked
 * against a seat's signature with `qgp_dsa87_verify`, so the test is
 * pinned to the LAYOUT, not merely self-consistent with the two helpers
 * it also exercises.
 *
 * The refusal matrix below (foreign chain id in the T3 HEADER — the
 * envelope wire carries no chain id, see nodus_chain_config.h's handler
 * note; non-member, wrong auth_kind, nonzero fee, TARGET_ACTIVE_COUNT
 * above the V2 ceiling, effective below the grace floor, the RETIRED
 * INFLATION_START parameter (tokenomics-v3 P2 — it replaces the ORC-6
 * monotonicity pair), the per-proposer rate limit) each drives ONE call
 * and checks `ok == false` plus a specific `reason` substring — never a
 * signature. "valid_before already past" is NOT in the matrix (HOW IT
 * CAN LIE 1b).
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build. Environment: none. SQLite
 * >= 3.35.0 (the S14 rung's own requirement, inherited from
 * `nodus_witness_v2_gen_derive_v3`).
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One `/tmp/test_cc_appr_*` directory per fixture, removed at close. A
 * case that aborts through CHECK leaves its directory behind (the
 * established convention of this tree's fixture-owning harness —
 * test_cmt_app.c's own "FIXTURE LIFETIME" note applies here unchanged).
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. The two-legs refusal (D-16 rev 7's approval-table membership check)
 *     is NOT covered here: building a second, DIFFERENT owned leg needs a
 *     second live runtime op with its own authority rule, and none of
 *     CORE's compiled ops fits this envelope's auth_kind-2 shape. A real
 *     gap, reported rather than faked.
 *  1b. The "valid_before already passed" refusal is NOT covered either,
 *     and cannot be with THIS fixture: it needs valid_before < h, and a
 *     freshly derived chain has h = tip+1 = 1, while
 *     nodus_chain_config_scalar_rules already forces valid_before >
 *     signed_at >= 1 — no integer satisfies both at tip == 0. See the
 *     comment where t_valid_before_past would have been, right before
 *     main()'s case table.
 *  2. `t_happy_path` proves quorum-and-above acceptance for ALL 7 seats
 *     asked; it does not separately re-drive the round-1/round-2 CLI
 *     shrink-and-reask flow (nodus-cli.c) — that flow's own correctness
 *     rests on this file's proof that EACH seat's approval, individually,
 *     is a digest the chain accepts, plus the CLI's own local
 *     `(sh, ep)` equality check before it trusts a reply.
 *  3. The rate-limit case shares `w->cc_rate_limit` with every other case
 *     in the same process (it is a field on the single `nodus_witness_t`
 *     fixture each case opens fresh) — case ORDER inside this file does
 *     not matter because each case opens its OWN fixture (fresh
 *     `nodus_witness_t`, fresh rate-limit table), but a future case
 *     sharing one fixture across two calls to the SAME sender_id would
 *     need to account for the 5 s cooldown explicitly, as
 *     `t_rate_limited_second_request` does.
 *  4. RED-first, honestly: on 7e5d867e (this package's base commit) this
 *     file does not compile — `nodus_witness_handle_cc_appr_req` and the
 *     verb-40/41 types are undeclared. There is no separate behavioral
 *     RED to demonstrate; the responder did not exist.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_v2_apply.h"
#include "witness/nodus_witness_v2_env.h"
#include "witness/nodus_witness_v2_produce.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_domreg.h"
#include "witness/nodus_witness_runtime.h"
#include "server/nodus_server.h"
#include "nodus/nodus_chain_config.h"

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_wire.h"
#include "transport/nodus_tcp.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "dnac/env_wire.h"
#include "dnac/env_preflight.h"
#include "witness/nodus_witness_emission.h"   /* DNAC_BLOCKS_PER_YEAR /
                                                * DNAC_DECIMAL_UNIT — the
                                                * fixture copied from
                                                * test_cmt_app.c needs them;
                                                * ORCHESTRATOR, W4-CC ORC-2 */

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                         \
    }                                                                     \
    g_checks++;                                                          \
} while (0)

static int g_checks = 0;

/* ══ deterministic REAL keys — test_cmt_app.c:207-240's shape ═════════ */

#define N_KEYS ((int)DNAC_COMMITTEE_SIZE)
#define GEN_TIME_MS 1767225600000ULL

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

/* One extra key (index N_KEYS, seed 0x40+N_KEYS) NOT in the committee —
 * used for the non-member refusal case. */
static keyset_t g_ks[N_KEYS + 1];

static int make_keys(void) {
    for (int i = 0; i < N_KEYS + 1; i++) {
        uint8_t seed[32], full[64];
        memset(seed, (uint8_t)(0x40 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_ks[i].pk, g_ks[i].sk, seed) != 0)
            return -1;
        if (qgp_sha3_512(g_ks[i].pk, QGP_DSA87_PUBLICKEYBYTES, full) != 0)
            return -1;
        memcpy(g_ks[i].voter, full, 32);
    }
    return 0;
}

static void rmrf(const char *path) {
    char cmd[300];
    if (!path || !path[0]) return;
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

/* ══ FIXTURE — a REAL version-3 chain — test_cmt_app.c:295-552's shape
 * (retyped here, this file's own copy: the established convention of
 * this tree's per-file fixture — test_cmt_node.c:316 does the same). ══ */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} cfgbox_t;

static void cfg_free(cfgbox_t *b) {
    if (b) { free(b->cfg); free(b->allocs); memset(b, 0, sizeof(*b)); }
}

/* tokenomics-v3 P2 (P2-4): the genesis INFLATION_START_BLOCK is RETIRED
 * — its only legal value is 0 and it is no longer committed as a param-3
 * row — so the `g_cfg_inflation_start` switch the two ORC-6 cases used
 * to flip is gone with them (see t_inflation_start_retired_refused). */
static int cfg_make_v3_real(cfgbox_t *b) {
    nodus_v2_gen_config_t *c;
    memset(b, 0, sizeof(*b));
    b->cfg    = calloc(1, sizeof(*b->cfg));
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) { cfg_free(b); return -1; }
    c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION_V3;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 0ULL;   /* tokenomics-v3 P2: RETIRED */
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = (uint16_t)N_KEYS;
    for (uint16_t k = 0; k < (uint16_t)N_KEYS; k++) {
        nodus_v2_gen_validator_t *v = &c->validators[k];
        memcpy(v->pubkey, g_ks[k].pk, DNAC_PUBKEY_SIZE);
        for (size_t bb = 0; bb < DNAC_PUBKEY_SIZE; bb++)
            v->unstake_destination_pubkey[bb] = (uint8_t)(v->pubkey[bb] ^ 0x5A);
        {
            static const char hexd[] = "0123456789abcdef";
            uint8_t d[64];
            qgp_sha3_512(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE, d);
            for (int i = 0; i < 64; i++) {
                v->unstake_destination_fp[2 * i]     = (uint8_t)hexd[d[i] >> 4];
                v->unstake_destination_fp[2 * i + 1] = (uint8_t)hexd[d[i] & 0x0F];
            }
            v->unstake_destination_fp[128] = 0;
        }
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (k + 1));
    }
    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[0].dest_binding);
    b->allocs[0].amount = 93000000000000000ULL;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) { cfg_free(b); return -1; }
    /* tokenomics-v3 P2 (P2-1): Rule P.2 now counts the reward reserve;
     * this fixture's allocation spends the whole supply and it is not a
     * reward test — no pool reserved. */
    c->reward_pool_initial = 0;
    c->genesis_time_ms = GEN_TIME_MS;
    c->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) { cfg_free(b); return -1; }
    return 0;
}

typedef struct {
    nodus_witness_t *w;
    nodus_server_t  *srv;
    cfgbox_t         box;
    char             dir[128];
    uint8_t          chain32[32];
} gfx_t;

static int gfx_open(gfx_t *g, const char *tag) {
    char path[600];
    memset(g, 0, sizeof(*g));
    if (cfg_make_v3_real(&g->box) != 0) return -1;
    if (nodus_witness_v2_gen_v3_validate(g->box.cfg) != 0) return -1;
    snprintf(g->dir, sizeof(g->dir), "/tmp/test_cc_appr_%s_XXXXXX", tag);
    if (!mkdtemp(g->dir)) return -1;
    if (nodus_witness_v2_gen_derive_v3(g->dir, g->box.cfg, g->chain32) != 0)
        return -1;
    {
        char hex[33];
        for (int i = 0; i < 16; i++) snprintf(hex + 2 * i, 3, "%02x", g->chain32[i]);
        hex[32] = '\0';
        snprintf(path, sizeof(path), "%s/witness_%s.db", g->dir, hex);
    }
    g->w   = calloc(1, sizeof(*g->w));
    g->srv = calloc(1, sizeof(*g->srv));
    if (!g->w || !g->srv) return -1;
    if (sqlite3_open_v2(path, &g->w->db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK)
        return -1;
    snprintf(g->w->data_path, sizeof(g->w->data_path), "%s", g->dir);
    g->w->cached_committee_epoch_start = UINT64_MAX;
    g->w->v2_successor     = true;
    g->w->v2_ingress_armed = true;
    memcpy(g->w->v2_chain32, g->chain32, 32);
    memcpy(g->srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(g->srv->identity.sk.bytes, g_ks[0].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(g->srv->identity.node_id.bytes, g_ks[0].voter, 32);
    g->w->server = g->srv;
    memcpy(g->w->my_id, g_ks[0].voter, 32);
    return 0;
}

static void gfx_close(gfx_t *g) {
    if (g->w) {
        if (g->w->db) sqlite3_close(g->w->db);
        free(g->w);
        g->w = NULL;
    }
    free(g->srv); g->srv = NULL;
    cfg_free(&g->box);
    rmrf(g->dir);
}

/* Rebind the fixture's OWN witness identity to committee seat `k` of
 * `g_ks` — this IS what makes the responder resolve "my own seat" as
 * `k` (nodus_witness_handle_cc_appr_req finds its seat by comparing
 * w->server->identity.pk against the resolved committee, exactly the
 * comparison this line sets up for). */
static void bind_identity(gfx_t *g, int k) {
    memcpy(g->srv->identity.pk.bytes, g_ks[k].pk, NODUS_PK_BYTES);
    memcpy(g->srv->identity.sk.bytes, g_ks[k].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(g->srv->identity.node_id.bytes, g_ks[k].voter, 32);
    memcpy(g->w->my_id, g_ks[k].voter, 32);
}

/* ══ a REAL loopback nodus_tcp_conn_t, so nodus_tcp_send has somewhere
 * real to write ═══════════════════════════════════════════════════════
 *
 * The responder is called DIRECTLY (never through
 * nodus_witness_dispatch_t3 — no CBOR envelope needed for the REQUEST,
 * this file builds the nodus_t3_msg_t in memory exactly as test_tier3.c
 * does), but it still calls nodus_tcp_send(conn, ...) on success or
 * refusal alike, so `conn` must be a REAL, CONNECTED nodus_tcp_conn_t —
 * test_cmt_live.c's own NULL-conn calls (nodus_witness_dispatch_t3(w,
 * NULL, ...), :684) never reach a verb whose handler replies, so that
 * shortcut does not apply here. */

typedef struct {
    nodus_tcp_t       tcp;
    nodus_tcp_conn_t *conn;
    int               lfd;
    int               afd;
} loop_t;

static int loop_open(loop_t *lp) {
    memset(lp, 0, sizeof(*lp));
    lp->lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lp->lfd < 0) return -1;
    int yes = 1;
    setsockopt(lp->lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(lp->lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(lp->lfd, 1) != 0) {
        close(lp->lfd); return -1;
    }
    socklen_t alen = sizeof(addr);
    getsockname(lp->lfd, (struct sockaddr *)&addr, &alen);

    if (nodus_tcp_init(&lp->tcp, -1) != 0) { close(lp->lfd); return -1; }
    lp->conn = nodus_tcp_connect(&lp->tcp, "127.0.0.1", ntohs(addr.sin_port));
    if (!lp->conn) { close(lp->lfd); return -1; }

    lp->afd = accept(lp->lfd, NULL, NULL);
    if (lp->afd < 0) return -1;

    for (int i = 0; i < 200 && lp->conn->state != NODUS_CONN_CONNECTED; i++)
        nodus_tcp_poll(&lp->tcp, 10);
    if (lp->conn->state != NODUS_CONN_CONNECTED) return -1;
    return 0;
}

static void loop_close(loop_t *lp) {
    if (lp->afd >= 0) close(lp->afd);
    if (lp->lfd >= 0) close(lp->lfd);
    nodus_tcp_close(&lp->tcp);
}

/* Read exactly one T3 frame off the accepted fd and decode it. */
static int loop_read_rsp(loop_t *lp, nodus_t3_msg_t *out) {
    static uint8_t buf[16384];
    size_t got = 0;
    for (;;) {
        struct pollfd pfd = { .fd = lp->afd, .events = POLLIN };
        if (poll(&pfd, 1, 2000) <= 0) return -1;
        ssize_t n = read(lp->afd, buf + got, sizeof(buf) - got);
        if (n <= 0) return -1;
        got += (size_t)n;
        nodus_frame_t frame;
        int rc = nodus_frame_decode(buf, got, &frame);
        if (rc < 0) return -1;
        if (rc > 0)
            return nodus_t3_decode(frame.payload, frame.payload_len, out);
        if (got >= sizeof(buf)) return -1;
    }
}

/* Ask the fixture's CURRENT identity (see bind_identity) for its
 * approval over `(e, e_len)`, through the REAL responder over the REAL
 * loopback conn. `header_chain32` lets the foreign-chain-id case supply
 * a mismatched value. */
static int ask(gfx_t *g, loop_t *lp, const uint8_t header_chain32[32],
              const uint8_t sender_id[32], const uint8_t *e, size_t e_len,
              nodus_t3_cc_appr_rsp_t *rsp_out) {
    nodus_t3_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = NODUS_T3_CC_APPR_REQ;
    msg.txn_id = 777;
    msg.header.version = NODUS_T3_BFT_PROTOCOL_VER;
    memcpy(msg.header.sender_id, sender_id, 32);
    memcpy(msg.header.chain_id, header_chain32, 32);
    msg.cc_appr_req.e     = e;
    msg.cc_appr_req.e_len = e_len;

    if (nodus_witness_handle_cc_appr_req(g->w, (struct nodus_tcp_conn *)lp->conn,
                                        &msg) != 0)
        return -1;
    nodus_t3_msg_t out;
    if (loop_read_rsp(lp, &out) != 0) return -1;
    if (out.type != NODUS_T3_CC_APPR_RSP) return -1;
    *rsp_out = out.cc_appr_rsp;
    return 0;
}

/* ══ the pre-auth CHAIN_CONFIG envelope — test_cmt_app.c's build_cc_env,
 * PARAMETERIZED and left UNSIGNED (pass 1 only): this file drives the
 * signatures through the RESPONDER, never locally. ═════════════════ */

#define CC_CALL_LEN 41u

typedef struct {
    uint8_t *bytes;
    size_t   len;
    dna_env_leg_in_t  leg;
    dna_env_in_t      env_in;
    dna_env_leg_ctx_t lctx;
    uint8_t call[CC_CALL_LEN];
    uint8_t *auth;
    uint32_t n_appr;
} pre_env_t;

static void pre_env_free(pre_env_t *e) {
    if (!e) return;
    free(e->bytes);
    free(e->auth);
    memset(e, 0, sizeof(*e));
}

static int pre_env_build(nodus_witness_t *w, uint64_t tip, uint32_t n_appr,
                         uint8_t param_id, uint64_t new_value,
                         uint64_t effective, uint64_t valid_before,
                         uint64_t fee_amount, uint8_t auth_kind,
                         pre_env_t *out, dna_env_preflight_t *pf) {
    dna_domain_manifest_t sys_man;
    memset(out, 0, sizeof(*out));
    if (nodus_witness_domreg_get(w, DNA_DOMAIN_SYSTEM, NULL, &sys_man, NULL) != 0)
        return -1;

    out->call[0] = param_id;
    uint64_t nonce = 1, signed_at = tip > 0 ? tip : 1;
    for (int i = 0; i < 8; i++) out->call[1 + i]  = (uint8_t)(new_value    >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) out->call[9 + i]  = (uint8_t)(effective    >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) out->call[17 + i] = (uint8_t)(nonce        >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) out->call[25 + i] = (uint8_t)(signed_at    >> (56 - 8 * i));
    for (int i = 0; i < 8; i++) out->call[33 + i] = (uint8_t)(valid_before >> (56 - 8 * i));

    out->n_appr = n_appr;
    size_t auth_len = 1 + NODUS_RT_AUTH_SIGNER_LEN + 2 +
                      (size_t)n_appr * NODUS_RT_AUTH_APPROVAL_LEN;
    out->auth = calloc(1, auth_len);
    if (!out->auth) return -1;

    out->leg.hdr.domain_id            = DNA_DOMAIN_SYSTEM;
    out->leg.hdr.runtime_op           = DNA_SYSRULE_CHAIN_CONFIG;
    out->leg.hdr.ruleset_version      = sys_man.ruleset_version;
    out->leg.hdr.access_mode          = DNA_ENV_ACCESS_INVOKE;
    out->leg.hdr.auth_kind            = auth_kind;
    out->leg.hdr.call_len             = CC_CALL_LEN;
    out->leg.hdr.auth_len             = (uint32_t)auth_len;
    out->leg.hdr.res_max_effects      = 4;
    out->leg.hdr.res_max_effect_bytes = 4096;
    out->leg.call_data = out->call;
    out->leg.auth_data = out->auth;

    out->env_in.expiry_height       = 0;
    out->env_in.fee_amount          = fee_amount;
    out->env_in.res_max_total_units = 200000;
    out->env_in.leg_count           = 1;
    out->env_in.legs                = &out->leg;

    if (dna_env_encoded_size(&out->leg, 1, &out->len) != 0) return -1;
    out->bytes = malloc(out->len);
    if (!out->bytes) return -1;

    out->lctx.domain_id       = DNA_DOMAIN_SYSTEM;
    out->lctx.ruleset_version = sys_man.ruleset_version;
    memcpy(out->lctx.ruleset_hash, sys_man.ruleset_hash, 64);

    size_t used = 0;
    if (dna_env_encode(&out->env_in, out->bytes, out->len, &used) != 0 ||
        used != out->len)
        return -1;
    if (dna_env_preflight(out->bytes, out->len, w->v2_chain32, tip + 1,
                          &out->lctx, 1, pf) != DNA_ENV_PF_OK)
        return -1;
    return 0;
}

/* Re-encode after auth bytes were filled (submitter + approvals) — the
 * two-pass discipline (env_preflight.h: auth_len IS committed). */
static int pre_env_reencode(pre_env_t *e, nodus_witness_t *w, uint64_t tip,
                            dna_env_preflight_t *pf) {
    size_t used = 0;
    if (dna_env_encode(&e->env_in, e->bytes, e->len, &used) != 0 || used != e->len)
        return -1;
    if (dna_env_preflight(e->bytes, e->len, w->v2_chain32, tip + 1, &e->lctx,
                          1, pf) != DNA_ENV_PF_OK)
        return -1;
    return 0;
}

/* ══ Cases ══════════════════════════════════════════════════════════ */

/* Happy path: ALL 7 real committee seats, asked through the REAL
 * responder, each returning a valid approval; assembled and handed to
 * nodus_witness_v2_env_dry_run — the per-item dry run CheckTx calls.
 * Plus an INDEPENDENT recomputation of set_hash/approval-digest against
 * the LAYOUT (not the two helpers under test), verified with
 * qgp_dsa87_verify. */
static int t_happy_path_all_seats(void) {
    gfx_t  g;
    loop_t lp;
    dna_env_preflight_t pf1, pf2;
    pre_env_t env;
    nodus_committee_member_t *cm = NULL;
    int cmn = 0;
    uint64_t tip = 0;

    CHECK(gfx_open(&g, "happy") == 0, "version-3 fixture");
    CHECK(loop_open(&lp) == 0, "loopback conn");
    CHECK(nodus_witness_v2_tip_height(g.w, &tip) == 0, "tip height");
    CHECK(nodus_committee_get_for_block_alloc(g.w, tip, &cm, &cmn) == 0 &&
          cmn == N_KEYS, "committee resolves to all 7 seats");

    CHECK(pre_env_build(g.w, tip, (uint32_t)cmn, 4 /* TARGET_ACTIVE_COUNT */,
                        7, tip + 1 + 200000, tip + 1 + 300000, 0,
                        NODUS_RT_AUTHKIND_DSA87_CC_V1, &env, &pf1) == 0,
          "pass-1 build");

    /* submitter: g_ks[0] (any valid key — the submitter need not be a
     * committee member, only the approvals are committee-gated). */
    {
        uint8_t *p = env.auth;
        p[0] = 1;
        memcpy(p + 1, g_ks[0].pk, DNAC_PUBKEY_SIZE);
        size_t sl = 0;
        CHECK(qgp_dsa87_sign(p + 1 + DNAC_PUBKEY_SIZE, &sl, pf1.auth_digest[0],
                             64, g_ks[0].sk) == 0, "submitter sign");
        p += 1 + NODUS_RT_AUTH_SIGNER_LEN;
        p[0] = (uint8_t)((uint32_t)cmn >> 8);
        p[1] = (uint8_t)cmn;
    }

    /* independent set_hash recomputation: "DNA.CCSET.v1"(16) ‖ count
     * u16 BE ‖ count x fp[64], fps in RESOLUTION order. */
    uint8_t indep_set_hash[64];
    {
        uint8_t pre[16 + 2 + 128 * 64];
        size_t off = 0;
        static const uint8_t tag[16] = {
            'D','N','A','.','C','C','S','E','T','.','v','1', 0,0,0,0 };
        memcpy(pre, tag, 16); off += 16;
        pre[off++] = (uint8_t)((uint32_t)cmn >> 8);
        pre[off++] = (uint8_t)cmn;
        for (int i = 0; i < cmn; i++) {
            uint8_t fp[64];
            CHECK(qgp_sha3_512(cm[i].pubkey, DNAC_PUBKEY_SIZE, fp) == 0, "fp");
            memcpy(pre + off, fp, 64); off += 64;
        }
        CHECK(qgp_sha3_512(pre, off, indep_set_hash) == 0, "set_hash");
    }

    /* `seat` here is the RESOLVED COMMITTEE POSITION (cm[seat]), never
     * assumed to equal a g_ks[] array index — the committee ranks by
     * stake DESC then a tiebreak hash (design §3.6), and every g_ks[]
     * entry here shares the SAME self_stake, so the resolved order is
     * whatever that tiebreak produces, not array order. Each seat's
     * OWN key is found by pubkey match, exactly the resolution
     * build_cc_env (test_cmt_app.c) and the CLI's own seat lookup use. */
    for (int seat = 0; seat < cmn; seat++) {
        int ki = -1;
        for (int k = 0; k < N_KEYS; k++) {
            if (memcmp(cm[seat].pubkey, g_ks[k].pk, DNAC_PUBKEY_SIZE) == 0) {
                ki = k;
                break;
            }
        }
        CHECK(ki >= 0, "resolved seat maps to one of this file's keys");
        bind_identity(&g, ki);
        /* ORCHESTRATOR correction (W4-CC ORC-4): this ONE witness stands
         * in for seven NODES. On the real network every seat is a
         * different node with its own, empty, per-proposer rate-limit
         * table, so one proposer's round-1 sweep never meets the 5 s
         * cooldown (NODUS_CC_RATE_LIMIT_WINDOW_MS) twice on one node.
         * Here all seven asks land on the SAME table with the SAME
         * sender, so seat 1 was refused "rate-limited (cooldown 5000ms,
         * elapsed 3ms)" — a fixture artefact, not the responder's rule
         * (that rule is pinned by t_rate_limited_second_request). Clear
         * the table as the next node would have it. */
        memset(&g.w->cc_rate_limit, 0, sizeof(g.w->cc_rate_limit));
        uint8_t *p = env.auth + 1 + NODUS_RT_AUTH_SIGNER_LEN + 2 +
                    (size_t)seat * NODUS_RT_AUTH_APPROVAL_LEN;
        nodus_t3_cc_appr_rsp_t rsp;
        memset(&rsp, 0, sizeof(rsp));
        CHECK(ask(&g, &lp, g.chain32, g_ks[0].voter, env.bytes, env.len,
                 &rsp) == 0, "ask seat");
        CHECK(rsp.ok, rsp.ok ? "seat approved" : rsp.reason);
        CHECK(rsp.seat == (uint16_t)seat, "seat index echoed");
        CHECK(memcmp(rsp.set_hash, indep_set_hash, 64) == 0,
              "set_hash matches independent recomputation");

        /* independent approval-digest recomputation against the LAYOUT:
         * "DNA.CCAPPR.v1"(16) ‖ leg_auth_digest(64) ‖ set_hash(64) ‖
         * epoch u64 BE ‖ seat u16 BE = 154 bytes. */
        uint8_t adg[64];
        {
            uint8_t pre[16 + 64 + 64 + 8 + 2];
            size_t off = 0;
            static const uint8_t tag[16] = {
                'D','N','A','.','C','C','A','P','P','R','.','v','1', 0,0,0 };
            memcpy(pre, tag, 16); off += 16;
            memcpy(pre + off, pf1.auth_digest[0], 64); off += 64;
            memcpy(pre + off, rsp.set_hash, 64); off += 64;
            for (int i = 0; i < 8; i++)
                pre[off + i] = (uint8_t)(rsp.epoch >> (56 - 8 * i));
            off += 8;
            pre[off++] = (uint8_t)((uint16_t)seat >> 8);
            pre[off++] = (uint8_t)seat;
            CHECK(off == sizeof(pre), "154-byte preimage");
            CHECK(qgp_sha3_512(pre, off, adg) == 0, "adg");
        }
        CHECK(qgp_dsa87_verify(rsp.sig, NODUS_SIG_BYTES, adg, 64,
                               cm[seat].pubkey) == 0,
              "seat signature verifies against the INDEPENDENT digest "
              "and the resolved committee pubkey");

        p[0] = (uint8_t)((uint16_t)seat >> 8);
        p[1] = (uint8_t)seat;
        memcpy(p + 2, rsp.sig, NODUS_SIG_BYTES);
    }

    CHECK(pre_env_reencode(&env, g.w, tip, &pf2) == 0, "pass-2 preflight");

    /* CHECKTX-P1 round 2: the signature-only entry
     * `nodus_witness_v2_env_authorize` is deleted; CheckTx's own check is
     * the per-item dry run (its authorization stage is the item loop's
     * `env_authorize_legs`), so that is what the assembled envelope is
     * handed here. The dry run also runs the SYSTEM exec hook, probe
     * only, at tip + 1. */
    char reason[256];
    reason[0] = '\0';
    nodus_v2_env_dry_run_t *dry = calloc(1, sizeof(*dry));   /* ~70 KB */
    CHECK(dry != NULL, "alloc");
    int arc = nodus_witness_v2_env_dry_run(g.w, env.bytes, env.len, NULL,
                                           dry, reason, sizeof(reason));
    nodus_witness_v2_env_dry_run_free(dry);
    free(dry);
    CHECK(arc == 0, reason[0] ? reason : "the CheckTx dry run accepted the "
                                        "fully-assembled envelope");

    /* ORCHESTRATOR addition (W4-CC ORC-5): the dispatch asked for the
     * assembled envelope to COMMIT through the engine, not only to pass
     * authorization. The dry run proves the seven signatures bind
     * the digest; only the SYSTEM exec hook's own rules — the quorum
     * count against the engine verdict (n_approvals >= dna_bft_quorum(N)),
     * the scalar/grace rules at the EXECUTION height — and the
     * chain_config_history write prove the responder signed something
     * the CHAIN accepts. Drive the Comet apply lane directly, the shape
     * test_cmt_app.c's duplicate-id probe uses: the caller owns the
     * BEGIN and the COMMIT (D-23 rev 5 (5)); block hash and validators
     * hash are stored verbatim and derive nothing, so any 64 bytes do. */
    {
        nodus_v2_block_t     *blk = calloc(1, sizeof(*blk));
        nodus_v2_envelope_t   one;
        nodus_v2_tx_result_t  res[1];
        sqlite3_stmt         *st = NULL;
        int64_t               rows = -1;

        CHECK(blk != NULL, "alloc");
        memset(&one, 0, sizeof(one));
        memset(res, 0, sizeof(res));
        one.env_bytes      = env.bytes;
        one.env_len        = env.len;
        blk->global_height = tip + 1;
        blk->epoch         = nodus_v2_epoch_for_height(tip + 1);
        blk->envs          = &one;
        blk->n_envs        = 1;
        blk->cmt.on        = true;
        memset(blk->cmt.block_hash,      0x42, 64);
        memset(blk->cmt.validators_hash, 0x43, 64);
        blk->cmt.results     = res;
        blk->cmt.results_cap = 1;

        CHECK(sqlite3_exec(g.w->db, "BEGIN IMMEDIATE", NULL, NULL, NULL)
                  == SQLITE_OK, "the transaction the Comet entry requires");
        int apc = nodus_witness_v2_apply_block(g.w, blk);
        CHECK(apc == 0, blk->out_reason[0] ? blk->out_reason
                                           : "the decided block applies");
        CHECK(blk->cmt.results_len == 1 && res[0].code == 0,
              "the envelope's item code is 0 — applied, not refused "
              "per item");
        CHECK(sqlite3_exec(g.w->db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK,
              "COMMIT");

        CHECK(sqlite3_prepare_v2(g.w->db,
                "SELECT COUNT(*) FROM chain_config_history "
                "WHERE param_id = 4 AND new_value = 7 AND effective_block = ?",
                -1, &st, NULL) == SQLITE_OK, "prepare");
        sqlite3_bind_int64(st, 1, (sqlite3_int64)(tip + 1 + 200000));
        if (sqlite3_step(st) == SQLITE_ROW) rows = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
        CHECK(rows == 1, "exactly one chain_config_history row for "
                         "(TARGET_ACTIVE_COUNT, 7, effective) was committed");
        free(blk);
    }

    pre_env_free(&env);
    free(cm);
    loop_close(&lp);
    gfx_close(&g);
    return 0;
}

/* One shared "build a pre-auth envelope, ask ONE seat, expect ok=false
 * with `reason` containing `expect_substr`" case, parameterized. */
static int refusal_case(const char *tag, int rebind_seat,
                        const uint8_t *header_chain32_or_null,
                        uint32_t n_appr, uint8_t param_id, uint64_t new_value,
                        uint64_t effective, uint64_t valid_before,
                        uint64_t fee_amount, uint8_t auth_kind,
                        const char *expect_substr) {
    gfx_t  g;
    loop_t lp;
    dna_env_preflight_t pf1;
    pre_env_t env;
    uint64_t tip = 0;

    CHECK(gfx_open(&g, tag) == 0, "version-3 fixture");
    CHECK(loop_open(&lp) == 0, "loopback conn");
    CHECK(nodus_witness_v2_tip_height(g.w, &tip) == 0, "tip height");

    CHECK(pre_env_build(g.w, tip, n_appr, param_id, new_value, effective,
                        valid_before, fee_amount, auth_kind, &env, &pf1) == 0,
          "pass-1 build");
    /* submitter, unconditionally — the responder's approval-table gate
     * runs on structural fields, never the submitter signature. */
    {
        uint8_t *p = env.auth;
        p[0] = 1;
        memcpy(p + 1, g_ks[0].pk, DNAC_PUBKEY_SIZE);
        size_t sl = 0;
        CHECK(qgp_dsa87_sign(p + 1 + DNAC_PUBKEY_SIZE, &sl, pf1.auth_digest[0],
                             64, g_ks[0].sk) == 0, "submitter sign");
        p += 1 + NODUS_RT_AUTH_SIGNER_LEN;
        p[0] = (uint8_t)(n_appr >> 8);
        p[1] = (uint8_t)n_appr;
    }

    if (rebind_seat >= 0) bind_identity(&g, rebind_seat);

    const uint8_t *hdr_chain = header_chain32_or_null ? header_chain32_or_null
                                                      : g.chain32;
    nodus_t3_cc_appr_rsp_t rsp;
    memset(&rsp, 0xAA, sizeof(rsp));
    CHECK(ask(&g, &lp, hdr_chain, g_ks[0].voter, env.bytes, env.len,
             &rsp) == 0, "ask");
    CHECK(!rsp.ok, "refused (not approved)");
    CHECK(strstr(rsp.reason, expect_substr) != NULL, rsp.reason);

    pre_env_free(&env);
    loop_close(&lp);
    gfx_close(&g);
    return 0;
}

static int t_foreign_chain_id(void) {
    uint8_t foreign[32];
    memset(foreign, 0x99, sizeof(foreign));
    /* effective/valid_before are 0 on purpose: the T3 header frame gate
     * fires BEFORE the envelope is even decoded, so the proposal's own
     * fields never reach a rule (a would-be "scalar rules rejected" is
     * unreachable here — the asserted reason proves which gate fired). */
    return refusal_case("foreign", 0, foreign, 5, 4, 7, 0, 0,
                        0, NODUS_RT_AUTHKIND_DSA87_CC_V1, "foreign chain id")
           == 0 ? 0 : 1;
}

static int t_not_committee_member(void) {
    /* rebind to g_ks[N_KEYS] — the 8th key, not in the committee. */
    return refusal_case("nonmember", N_KEYS, NULL, 5, 4, 7,
                        1000000000ULL, 1000100000ULL, 0,
                        NODUS_RT_AUTHKIND_DSA87_CC_V1, "not a committee seat")
           == 0 ? 0 : 1;
}

static int t_wrong_auth_kind(void) {
    return refusal_case("authkind1", 0, NULL, 5, 4, 7,
                        1000000000ULL, 1000100000ULL, 0,
                        NODUS_RT_AUTHKIND_DSA87_MULTI_V1,
                        "auth_kind-2") == 0 ? 0 : 1;
}

static int t_nonzero_fee(void) {
    return refusal_case("fee", 0, NULL, 5, 4, 7,
                        1000000000ULL, 1000100000ULL, 1 /* fee */,
                        NODUS_RT_AUTHKIND_DSA87_CC_V1, "zero-fee")
           == 0 ? 0 : 1;
}

static int t_target_above_ceiling(void) {
    /* param 4 = TARGET_ACTIVE_COUNT, value 33 > NODUS_V2_ACTIVE_SET_MAX
     * (32 since tokenomics-v3 P3-7; was 31 > 30 — 31 is now a LEGAL
     * target and would not be refused) */
    return refusal_case("target33", 0, NULL, 5, 4, 33,
                        1000000000ULL, 1000100000ULL, 0,
                        NODUS_RT_AUTHKIND_DSA87_CC_V1,
                        "active-set ceiling") == 0 ? 0 : 1;
}

static int t_effective_below_floor(void) {
    /* A freshly derived version-3 chain always has tip == 0 (no block
     * rows at all — build_cc_env's own comment, this file's model, says
     * so and t_happy_path_all_seats's tip read confirms it), so the
     * candidate height h = tip+1 = 1 is known without opening a probe
     * fixture. effective == h is always below ANY nonzero grace floor. */
    return refusal_case("efffloor", 0, NULL, 5, 4, 7,
                        1 /* effective == h */, 2 /* valid_before > h */, 0,
                        NODUS_RT_AUTHKIND_DSA87_CC_V1,
                        "grace floor") == 0 ? 0 : 1;
}

/* NOT COVERED, and why: "H > valid_before" (freshness) needs
 * valid_before < h. On a freshly derived chain h = tip+1 = 1, so that
 * needs valid_before == 0 — but nodus_chain_config_scalar_rules already
 * requires valid_before > signed_at, and signed_at is nonzero by the
 * SAME rule (cc_appr_rules_chain_config's signed_at = tip>0 ? tip : 1,
 * so signed_at == 1 here), forcing valid_before >= 2. No integer
 * satisfies both at tip == 0: this refusal is UNREACHABLE against this
 * fixture without first advancing the chain past height 1, which this
 * file's fixture does not do. A real gap, not a substitute. */

/* tokenomics-v3 P2 (P2-4) — INFLATION_START_BLOCK (param id 3) is
 * RETIRED, exactly as MAX_TXS_PER_BLOCK (id 1) was: the responder's
 * scalar-rules gate refuses ANY param-3 proposal, whatever its value —
 * here the very "start inflation at a future height" proposal the ORC-6
 * pair used to accept on a chain born with inflation off. The two ORC-6
 * cases (t_inflation_start_from_off_signs, a POSITIVE case, and its
 * monotonicity control t_inflation_start_past_candidate_refused) are
 * DELETED with the rule they pinned: the monotonicity check and the
 * SYSTEM adapter's op 3 it read are gone, and a genesis no longer seeds a
 * param-3 row. RED on the pre-P2 tree: the responder signed this
 * proposal (the exact ORC-6 positive case). */
static int t_inflation_start_retired_refused(void) {
    return refusal_case("inflretired", 0, NULL, 5,
                        DNAC_CFG_INFLATION_START_BLOCK,
                        1 + 5000, 1 + 200000, 1 + 300000, 0,
                        NODUS_RT_AUTHKIND_DSA87_CC_V1,
                        "scalar rules rejected") == 0 ? 0 : 1;
}

/* The per-proposer rate limit (unchanged, nodus_cc_rate_limit_check):
 * the SAME sender_id asked twice for the SAME seat within the 5 s
 * cooldown — the second request is refused "rate-limited", never
 * signed. D-16 rev 7's own design tension (BLOCKED ON, see the CLI
 * report): a round-2 rebuild re-asking the same accepting seat within
 * the cooldown hits exactly this refusal. */
static int t_rate_limited_second_request(void) {
    gfx_t  g;
    loop_t lp;
    dna_env_preflight_t pf1;
    pre_env_t env;
    uint64_t tip = 0;

    CHECK(gfx_open(&g, "ratelimit") == 0, "version-3 fixture");
    CHECK(loop_open(&lp) == 0, "loopback conn");
    CHECK(nodus_witness_v2_tip_height(g.w, &tip) == 0, "tip height");
    CHECK(pre_env_build(g.w, tip, 5, 4, 7, tip + 1000000, tip + 1100000, 0,
                        NODUS_RT_AUTHKIND_DSA87_CC_V1, &env, &pf1) == 0,
          "pass-1 build");
    {
        uint8_t *p = env.auth;
        p[0] = 1;
        memcpy(p + 1, g_ks[0].pk, DNAC_PUBKEY_SIZE);
        size_t sl = 0;
        CHECK(qgp_dsa87_sign(p + 1 + DNAC_PUBKEY_SIZE, &sl, pf1.auth_digest[0],
                             64, g_ks[0].sk) == 0, "submitter sign");
    }
    bind_identity(&g, 1);

    nodus_t3_cc_appr_rsp_t rsp1, rsp2;
    memset(&rsp1, 0, sizeof(rsp1));
    memset(&rsp2, 0xAA, sizeof(rsp2));
    CHECK(ask(&g, &lp, g.chain32, g_ks[0].voter, env.bytes, env.len,
             &rsp1) == 0, "first ask");
    CHECK(rsp1.ok, "first request approved");
    CHECK(ask(&g, &lp, g.chain32, g_ks[0].voter, env.bytes, env.len,
             &rsp2) == 0, "second ask");
    CHECK(!rsp2.ok, "second request (same sender, same seat, <5s) refused");
    CHECK(strstr(rsp2.reason, "rate-limited") != NULL, rsp2.reason);

    pre_env_free(&env);
    loop_close(&lp);
    gfx_close(&g);
    return 0;
}

int main(void) {
    static const struct {
        const char *name;
        int (*fn)(void);
    } cases[] = {
        { "happy_path_all_seats",       t_happy_path_all_seats },
        { "foreign_chain_id",           t_foreign_chain_id },
        { "not_committee_member",       t_not_committee_member },
        { "wrong_auth_kind",            t_wrong_auth_kind },
        { "nonzero_fee",                t_nonzero_fee },
        { "target_above_ceiling",       t_target_above_ceiling },
        { "effective_below_floor",      t_effective_below_floor },
        { "inflation_start_retired_refused",
                                        t_inflation_start_retired_refused },
        { "rate_limited_second_request", t_rate_limited_second_request },
    };
    size_t failed = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    if (make_keys() != 0) {
        fprintf(stderr, "test_cc_appr: key generation failed\n");
        return 1;
    }
    for (size_t i = 0; i < ncases; i++) {
        int rc = cases[i].fn();
        fprintf(stderr, "%-30s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) failed++;
    }
    fprintf(stderr, "test_cc_appr: %zu/%zu cases passed, %d checks\n",
            ncases - failed, ncases, g_checks);
    return failed ? 1 : 0;
}
