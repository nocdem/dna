/**
 * @file nodus/tests/test_cmt_live.c
 * @brief FLEET-TM-R3 W3 package C2a — THE SERVER BINDING, DRIVEN LIVE: the
 *        first test in this tree to bring up a `nodus_witness_t` through
 *        the REAL `nodus_witness_init` -> `nodus_witness_tick` path over a
 *        REAL version-3 chain (`nodus_witness_v2_gen_derive_v3`, real
 *        ML-DSA-87 keys) and observe the cometbft startup table
 *        (`nodus_witness_cmt_node.{h,c}`) and the transport glue
 *        (`nodus_witness_cmt_net.{h,c}`) run under their own production
 *        entry points — `nodus_witness_cmt_live_init` (exported delta 10,
 *        was `static witness_cmt_live_init`), `witness_cmt_tick`,
 *        `witness_cmt_now`, `witness_cmt_raw_sign` and
 *        `nodus_witness_dispatch_t3` (nodus_witness.c) — rather than the
 *        package's own unit-level shims (`test_cmt_node.c`'s `run_handshake`
 *        never reaches `nodus_witness_init`; `test_cmt_net.c` and
 *        `test_witness_protocol_version_gate.c` build a bare
 *        `nodus_witness_t` with `w->server` left NULL specifically so a
 *        dummy peer connection is never dereferenced — see this file's own
 *        "HOW IT CAN LIE" (2) for why that shortcut is NOT available here).
 *
 * ═══ THE BLOCKER THIS FILE FOUND BEFORE WRITING A SINGLE CASE ═══════════
 * The dispatch for this package asks for "ONE validator over a real
 * version-3 chain" that "blocks commit on the tick alone
 * (onlyValidatorIsUs)". That scenario CANNOT be built on this chain:
 *
 *   - Genesis validation demands EXACTLY `DNAC_COMMITTEE_SIZE` (7)
 *     validators — Rule P.1, `nodus_witness_v2_gen.c:582-584`
 *     (`cfg->n_validators != (uint16_t)DNAC_COMMITTEE_SIZE` is a hard
 *     refusal, not a floor with an override knob: `DNAC_COMMITTEE_SIZE`
 *     is a plain `#define` at `dnac/include/dnac/dnac.h:187`, never
 *     guarded by `#ifndef`, unlike `DNAC_EPOCH_LENGTH`, which the Genesis
 *     Protocol harness DOES override at compile time).
 *   - Every validator's stake is pinned to the SAME constant —
 *     `nodus_witness_v2_gen.c:600-603`
 *     (`v->self_stake != DNAC_SELF_STAKE_AMOUNT` is refused for EVERY
 *     entry) — so no genesis can hand one key a dominant share of voting
 *     power either.
 *
 * `onlyValidatorIsUs` in the reference means `len(validators) == 1`. On
 * this chain `len(validators)` is always 7, with equal weight, so a
 * SINGLE live process holds at most 1/7 of the voting power and can never
 * reach the +2/3 threshold (5 of 7) needed to commit a block — no matter
 * how correct `witness_cmt_tick` / `cmt_cs_step` / the transport glue are.
 * Demonstrating actual block PRODUCTION honestly needs either all seven
 * processes live (a multi-node harness — `test_cmt_multinode.h` is being
 * extended by another writer in this wave, outside this file's whitelist)
 * or bypassing the genesis floor above, which is project policy, not a
 * fixture knob. This is reported to the ORCHESTRATOR as BLOCKED, not
 * worked around; see the per-case notes below for exactly what that
 * blocks and what is still genuinely exercised with one live process out
 * of seven.
 *
 * ── WHAT EACH CASE PROVES (and what the blocker above leaves BLOCKED) ──
 *  1. `t_genesis_wait_and_peer_gate`
 *     (a) BEFORE the document's `genesis_time_ms`: `witness->cmt_live`
 *         stays false across a bounded run of ticks — `witness_cmt_tick`'s
 *         own genesis-time gate (nodus_witness.c:1611-1638) never starts
 *         the two reactors while `now < genesis_time`.
 *     (b) a peer marked `identified` with a connection BEFORE that point
 *         is NOT admitted into the consensus reactor's peer set
 *         (`conr->peers[i].in_set == false`) — `net_scan_peers`'s own
 *         guard, "a peer can only be admitted once BOTH reactors are
 *         running" (nodus_witness_cmt_net.c:519).
 *     (c) once real time crosses `genesis_time_ms`, the NEXT tick flips
 *         `cmt_live` to true, starts both reactors
 *         (`n->cs_started == true`) and, in that SAME call, falls
 *         through into the peer-set scan (`witness_cmt_tick`'s (b)(c)(d)
 *         run unconditionally after the genesis-time block, no `return`
 *         between them, nodus_witness.c:1611-1698) — so the SAME peer
 *         slot, marked up before the wait began and unchanged since, is
 *         ALREADY admitted (`conr->peers[i].in_set == true`) by the time
 *         this call returns.
 *     (d) one further explicit tick, with nothing about the slot
 *         changed, leaves it admitted — `net_scan_peers` re-scanning an
 *         unchanged "up" slot is a no-op (nodus_witness_cmt_net.c:
 *         527-533), never a second add and never a drop.
 *     (e) clearing the slot and ticking once more removes it again
 *         (`in_set == false`) — the down transition
 *         (nodus_witness_cmt_net.c:557-560).
 *     BLOCKED: nothing here proves a block commits — see the file header.
 *  2. `t_version_gate_verb35` — THE REAL `nodus_witness_dispatch_t3`,
 *     never `nodus_cmt_net_receive` called directly (that is
 *     `test_cmt_net.c`'s ground): a signed `w_cmt_state` envelope
 *     (a real marshalled `NewRoundStep`, `cmt_msg_to_proto` +
 *     `cmt_pb_cons_message_marshal`, the same idiom `test_cmt_net.c`'s
 *     `build_new_round_step` uses) from a SECOND identity registered in
 *     `witness->roster` and admitted into `witness->peers[]` is ACCEPTED
 *     at header version `NODUS_T3_BFT_PROTOCOL_VER` (7) — observed
 *     through `cmt_ps_get_round_state` on that peer's OWN `cmt_ps_t`
 *     inside the live `cmt_conr_t` — and REFUSED (no round-state change)
 *     at version 6 and at 8, proven NON-VACUOUSLY: each wrong-version
 *     attempt carries a DIFFERENT height than the accepted one, so an
 *     accidental acceptance would show up as the peer's height moving.
 *  3. `t_checktx_funded_and_forged` — a REAL claim
 *     (`dna_claim_t`, `dnac/manifest_wire.h`) against the genesis
 *     distribution allocation this chain's own document funds
 *     (`allocs[0]`, bound to validator 0's pubkey, exactly the shape
 *     `test_cmt_app.c`'s claim cases build), submitted through the LIVE
 *     node's own mempool (`n->mem`, via `cmt_mem_check_tx` — the real
 *     `cmt_mem_t` the startup table built, not a bare `cmt_mem_app_t`
 *     row) is admitted AT ONCE (`CMT_OK`, `res.code == CMT_MEM_CODE_TYPE_
 *     OK`); the IDENTICAL claim fields re-signed with a DIFFERENT
 *     validator's secret key is refused (`res.code != CMT_MEM_CODE_TYPE_
 *     OK`) — the signature check inside `nodus_witness_v2_claim_admit`,
 *     reached from `nodus_cmt_app_check_tx`'s CLAIM branch
 *     (nodus_witness_cmt_app.c:341-349) via
 *     `verify_v2_successor_claim`(nodus_witness_verify.c:531-615, "sig+dest"
 *     at :523). BLOCKED: "lands in a later block" — no block ever
 *     commits (the file header's blocker); this case proves ADMISSION
 *     only, never inclusion.
 *  4. `t_restart_reopens_same_role` — `nodus_witness_close` then a second
 *     `nodus_witness_init` over the SAME `nodus_server_t` and the SAME
 *     data directory succeeds and reproduces the SAME role
 *     (`v2_successor == true`, the SAME `v2_chain32`, the startup table
 *     rebuilds) — this is the restart path the dispatch asked for, but
 *     BLOCKED at "production resumes (height advances past the tip)":
 *     there is no tip to advance past, because no block ever committed.
 *     What is proven is narrower and stated as such: a restart of a node
 *     that has produced NOTHING does not corrupt or refuse its own chain.
 *  5. `t_mesh_ticks_on_v3` — FLEET-TM-R3 W3 DELTA 2, a live-node defect
 *     found by the ORCHESTRATOR reading `nodus_witness_tick`: on a
 *     version-3 chain the function used to return right after
 *     `witness_cmt_tick` and NEVER reach `nodus_witness_peer_tick` or
 *     the 60 s roster refresh — so on a real node no roster witness was
 *     ever dialed, IDENT was never exchanged, and both reactors carried
 *     zero peers forever. A second genesis witness (`g_ks[1]`, not self)
 *     is registered in `witness->roster` with a syntactically valid but
 *     unreachable address; ticking the LIVE witness through the REAL
 *     `nodus_witness_tick` (never `witness_cmt_tick` directly) must make
 *     `nodus_witness_peer_tick`'s reconnect loop create a `witness->
 *     peers[]` entry for that witness_id, with `last_attempt` nonzero —
 *     evidence the dial loop actually ran. Was RED against DELTA 2's
 *     tick body; GREEN since DELTA 3, against the C2a writer's fix
 *     (`witness_mesh_tick`, nodus_witness.c:2379-2430, called before
 *     `witness_cmt_tick` on a version-3 chain, call site :2502-2504). The
 *     SAME fix exposed a SECOND live-node defect this case now also
 *     guards against by priming `witness->last_epoch` — see the case's
 *     own doc comment and item 8 below.
 *  6. `t_adopt_then_live` — R3-W3-C2a-18 (delta 10), a live-node defect
 *     the third Genesis Protocol sweep found: mid-life adoption
 *     (`join_adopt`) held the chain role but never built the cometbft
 *     startup table, so an adopted joiner never went live and never
 *     caught up. Reproduces the exact sequence `join_adopt` puts a
 *     witness through — pre-genesis init, a chain derived directly into
 *     the SAME data directory, the SAME `nodus_witness_scan_chain_db`
 *     call `join_adopt` makes — then proves the newly-EXPORTED
 *     `nodus_witness_cmt_live_init` closes the gap: builds the four
 *     pointers, and a bounded tick loop past genesis time reaches
 *     `cmt_live == true`. Does NOT drive `join_adopt` itself (that needs
 *     a live two-process genesis bundle transfer, C2c/C2d's ground) —
 *     see the case's own doc comment for exactly what is and is not
 *     proven, and why "RED before this delta" honestly means the symbol
 *     did not exist to call, not a behavioural failure.
 *  7. Every case prints `nodus_cmt_net_recv_arena_used(net)` once at its
 *     own end — the dispatch's "after every committed block" cannot be
 *     honoured (no block ever commits); this reports the measured runway
 *     after whatever cometbft-envelope traffic that case actually drove.
 *
 * ── WHAT IT REQUIRES ────────────────────────────────────────────────────
 * Compile flags: none beyond a default build (this file needs nothing
 * `test_cmt_node.c` / `test_cmt_app.c` / `test_cmt_net.c` do not already
 * need). Environment: none — `NODUS_FAULT_*` is never read on this path.
 * SQLite >= 3.35.0 (S14 rung, enforced by the derivation itself). The
 * WALL CLOCK is left REAL throughout (`witness_cmt_now` reads
 * `CLOCK_REALTIME`) — this is the ONE place D-23 rev 7 (19) / the
 * consensus reference itself reads the clock this way (the genesis-time
 * wait), so faking it would test a mechanism this file is not allowed to
 * invent (`PRIMARY OBJECTIVE: DETERMINISM`'s named exception). Every wait
 * on that clock is expressed as a BOUNDED number of `nodus_witness_tick`
 * calls with a `usleep` between them, never a bare `sleep`.
 *
 * ── WHAT IT LEAVES BEHIND ───────────────────────────────────────────────
 * One `/tmp/test_cmt_live_*` directory per case, removed at that case's
 * own close. A case that aborts through `CHECK` leaves its directory
 * behind (the same discipline `test_cmt_node.c` states for itself).
 * Heap-allocated `nodus_server_t` / `nodus_witness_t` (both multi-MB) per
 * case, freed on every path.
 *
 * ── HOW IT CAN LIE ──────────────────────────────────────────────────────
 *  1. ONE VALIDATOR ONLY, OF SEVEN. See the file-header blocker: nothing
 *     in this file exercises the +2/3 quorum path, proposal selection
 *     among competing validators, view-change / round-skip under
 *     contention, or anything downstream of an actual COMMIT (finalize,
 *     apply, the ledger's state_root). A green run here says the startup
 *     table constructs, the genesis-time gate and peer-admission gate
 *     hold, the version gate for verb 35-39 still refuses a wrong header
 *     version through the REAL dispatcher, and CheckTx admission/refusal
 *     works over the real mempool — and NOTHING about consensus among a
 *     live seven-node set.
 *  2. THE SECOND IDENTITY (`peers[1]`) NEVER HAS A REAL SOCKET. Its
 *     `w->peers[1].conn` is a REAL, heap-allocated, ZEROED
 *     `nodus_tcp_conn_t *` — deliberately NOT the raw non-NULL integer
 *     pointer `test_cmt_net.c` / `test_witness_protocol_version_gate.c`
 *     use, because THIS witness's `w->server` is REAL (required for
 *     `witness_cmt_raw_sign` and the whole `nodus_witness_init` path),
 *     and a real `w->server` means the consensus reactor's own gossip
 *     WILL eventually call `net_send` -> `nodus_tcp_send` on that peer
 *     slot once it is admitted. `nodus_tcp_conn_t`'s zero value is
 *     `NODUS_CONN_CLOSED` (`nodus_tcp.h:28`, value 0), and
 *     `nodus_tcp_send_progress` (`nodus_tcp.c:1045-1048`) returns -1 on
 *     `conn->state == NODUS_CONN_CLOSED`, before touching `ip` or any
 *     write buffer — it DOES read `conn->fd` on that path, but only as
 *     an integer for the log line ("send: connection closed (fd=%d)",
 *     `nodus_tcp.c:1046`), never dereferenced or written through; on a
 *     zeroed `calloc`'d struct that read is `0`, harmless — confirmed by
 *     reading that function to its early return, not assumed. So every
 *     gossip attempt toward this peer fails CLEANLY (`net_send` returns
 *     false); it never proves an actual `nodus_tcp_send` over a live
 *     socket succeeds. The dummy connection
 *     is never `nodus_tcp_disconnect`d either: this file never lets a
 *     slot it owns reach `close_pending` (it clears `conn`/`identified`
 *     directly, the same down-transition `net_scan_peers` handles without
 *     touching the transport), and `nodus_witness_close` ->
 *     `nodus_witness_peer_close` only clears slots below `w->peer_count`
 *     (`nodus_witness_peer.c:1972`), which this file never increments —
 *     so the real teardown path never touches this pointer either. It is
 *     freed by hand, by this file, after every slot referencing it is
 *     cleared.
 *  3. THE CLAIM ADMISSION CASE NEVER REACHES A BLOCK, so it says nothing
 *     about `nodus_witness_v2_claim_admit`'s CROSS-BLOCK spent-set check
 *     or the pending-mempool nullifier dedup once TWO claims of the same
 *     allocation are both pending — it proves exactly one accept and one
 *     signature-refusal, both at CheckTx.
 *  4. THE GENESIS-TIME WAIT IS A REAL WALL-CLOCK RACE, BOUNDED GENEROUSLY.
 *     `GENESIS_LEAD_MS` (1200 ms) must be large enough that this file's
 *     OWN setup (derive a 7-validator chain, open it through the full
 *     `nodus_witness_init` path) completes before that instant, or the
 *     "before genesis time" observation (1a/1b above) is vacuous — the
 *     chain would already be live by the first tick. `WAIT_TICKS_MAX`
 *     (200 ticks x 50 ms = 10 s) is the bound on waiting for `cmt_live`
 *     to flip; a run this slow anywhere else in the tree would already be
 *     a P0. Distinguished from a NODE FAULT: the wait loop checks
 *     `witness->running` on every iteration and fails with a distinct
 *     message ("node halted") the moment it goes false, rather than
 *     letting the bound expire and reporting an ambiguous timeout.
 *  5. THIS IS THE FIRST TEST IN THE TREE TO DRIVE `nodus_witness_init`
 *     (and therefore `witness_post_open_gate`'s S14-store / S7-pool /
 *     V2-finalize-selfcheck / chain-role gates) OVER A FRESHLY DERIVED
 *     VERSION-3 CHAIN. `test_cmt_node.c`'s own fixture (`gfx_open`)
 *     bypasses ALL of that: it opens the database with a bare
 *     `sqlite3_open_v2` and sets `v2_successor` / `v2_chain32` BY HAND. A
 *     failure inside `witness_post_open_gate` or `nodus_witness_scan_
 *     chain_db` on this file's chain is therefore untested ground closing
 *     for the first time, not a fixture defect to fix quietly.
 *  6. `wh.cid` (the frame's `header.chain_id`) is set to this chain's real
 *     32-byte id for every signed frame this file sends, but nothing on
 *     the receive path compares it to anything today (confirmed by grep:
 *     no `header.chain_id` / `hdr->chain_id` read in `nodus_witness.c`,
 *     `nodus_witness_cmt_net.c` or `nodus_tier3.c` outside of encode/
 *     decode) — this file's version-gate case does not exercise that
 *     field's eventual enforcement, only its presence on the wire.
 *  7. `t_checktx_funded_and_forged`'s REFUSAL half is meaningless without
 *     its own PRECONDITION. `verify_v2_successor_tx`'s FIRST gate is
 *     `nodus_witness_v2_ingress_is_armed` (nodus_witness_verify.c:
 *     653-657), reached before any claim/signature work — a CLOSED gate
 *     refuses the funded claim and the forged claim IDENTICALLY, for a
 *     reason that has nothing to do with either one's signature. Were
 *     the precondition CHECK above removed (or ignored), "the forged
 *     claim is refused" would still read as a PASS while proving nothing
 *     about the signature check it names — a closed-gate refusal and a
 *     signature-refusal produce the SAME observable (`res.code !=
 *     CMT_MEM_CODE_TYPE_OK`). In THIS worktree the gate IS closed (the
 *     pre-C2c activation preflight reports `SCHEMA_UNSUPPORTED` for a
 *     version-3/S14 chain and never arms ingress), so the precondition
 *     CHECK fails first and names the real cause instead of letting the
 *     case report a false, vacuous green.
 *  8. `t_mesh_ticks_on_v3` PROVES THE DIAL ATTEMPT, NOTHING FURTHER. There
 *     is no second live process on the other end of that address, so
 *     this case observes `nodus_tcp_connect` being CALLED and a peer
 *     table entry with `last_attempt` set — never a connection reaching
 *     `NODUS_CONN_CONNECTED`, never a `w_ident` exchange, never
 *     `identified` becoming true. It also drives ONLY the per-tick
 *     reconnect loop; the SEPARATE 60 s roster refresh
 *     (`nodus_witness_rebuild_roster_from_peers`, epoch-gated) is not
 *     exercised by a bounded test and is reported here as coverage that
 *     did NOT happen, not folded into this case's green.
 *  9. ORCHESTRATOR DELTA 3 — `t_version_gate_verb35` and
 *     `t_mesh_ticks_on_v3` both PRIME `witness->last_epoch` to "now"
 *     immediately after `live_open`, deliberately holding the 60 s epoch
 *     roster refresh off for their whole bounded tick window. Neither
 *     case exercises that refresh AT ALL — coverage that did not happen
 *     here, named rather than silently absent. On a REAL node the
 *     refresh runs every 60 s regardless (`witness_mesh_tick`,
 *     nodus_witness.c:2379-2430) and REBUILDS `witness->roster` from the
 *     DHT peer registry (`nodus_witness_rebuild_roster_from_peers`): a
 *     witness this node has hand-registered but that is absent from that
 *     registry — exactly `t_version_gate_verb35`'s and
 *     `t_mesh_ticks_on_v3`'s `g_ks[1]`, which never publishes anything to
 *     a DHT in either fixture — WOULD be dropped from the roster on the
 *     next real refresh. Both cases' own roster-survival precondition
 *     CHECKs prove only that the refresh did not fire DURING the case,
 *     never that a real node's roster would keep this witness past 60 s.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <sqlite3.h>

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/nodus_sign.h"          /* nodus_random                  */

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_v2_gen.h"
#include "witness/nodus_witness_v2_claims.h"
#include "witness/nodus_witness_v2_gate.h"   /* nodus_witness_v2_ingress_is_armed */
#include "witness/nodus_witness_emission.h"   /* DNAC_DECIMAL_UNIT       */
#include "witness/nodus_witness_cmt_node.h"
#include "witness/nodus_witness_cmt_net.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"        /* nodus_time_now, nodus_tcp_conn_t */
#include "protocol/nodus_tier3.h"
#include "nodus/nodus_types.h"

#include "dnac/dnac.h"
#include "dnac/manifest_wire.h"         /* dna_claim_t, dna_gman_t        */
#include "dnac/cmt_mem.h"
#include "dnac/cmt_ps.h"
#include "dnac/cmt_msgs.h"
#include "dnac/cmt_pb.h"

#define CHECK(cond, msg) do {                                              \
    if (!(cond)) {                                                         \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                (msg));                                                    \
        return 1;                                                          \
    }                                                                      \
    g_checks++;                                                            \
} while (0)

static int g_checks = 0;

/* ══ deterministic REAL keys — the full 7-validator committee ═══════════
 * DNAC_COMMITTEE_SIZE (7) is a hard genesis invariant (see the file
 * header's blocker); every case in this file derives the SAME 7-key
 * chain and brings up ONE live process holding key 0's identity. Key 1
 * is the "second identity" the version-gate case dispatches frames from,
 * and the wrong-signer key the CheckTx forgery case signs with. */
#define N_KEYS ((int)DNAC_COMMITTEE_SIZE)

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t voter[32];
} keyset_t;

static keyset_t g_ks[N_KEYS];

static int make_keys(void)
{
    int i;

    for (i = 0; i < N_KEYS; i++) {
        uint8_t seed[32], full[64];

        memset(seed, (uint8_t)(0x60 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_ks[i].pk, g_ks[i].sk, seed) != 0) {
            return -1;
        }
        if (qgp_sha3_512(g_ks[i].pk, QGP_DSA87_PUBLICKEYBYTES, full) != 0) {
            return -1;
        }
        memcpy(g_ks[i].voter, full, 32);
    }
    return 0;
}

/* test_cmt_app.c / test_cmt_node.c:211-224 `hex_lower_fp`, retyped here —
 * each test file in this package keeps its own copy (the function is
 * `static` in each). */
static void hex_lower_fp(const uint8_t *src, size_t src_len, uint8_t *out129)
{
    static const char hexd[] = "0123456789abcdef";
    uint8_t d[64];
    int i;

    qgp_sha3_512(src, src_len, d);
    for (i = 0; i < 64; i++) {
        out129[2 * i]     = (uint8_t)hexd[d[i] >> 4];
        out129[2 * i + 1] = (uint8_t)hexd[d[i] & 0x0F];
    }
    out129[128] = 0;
}

static uint64_t now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

#define TREASURY_RAW  93000000000000000ULL   /* test_cmt_app.c:155/182   */
/* "HOW IT CAN LIE" (4): must exceed this file's own setup time
 * (derive_v3 + nodus_witness_init over a 7-validator chain). */
#define GENESIS_LEAD_MS  3000ULL  /* per the dispatch: "~3 s in the future" */
#define TICK_SLEEP_US    50000  /* 50 ms, matches D-23 rev 7 (19)'s poll  */
#define WAIT_TICKS_MAX   200    /* 200 * 50 ms = 10 s bound               */

/* ══ FIXTURE — a REAL version-3 chain, derived exactly as
 *    test_cmt_node.c's cfg_make_v3_real / gfx_open, EXCEPT genesis_time_ms
 *    is a caller-supplied near-future instant, never the fixed constant
 *    those files use, and the witness/server are brought up through the
 *    REAL nodus_witness_init path rather than a hand-built handle. ═══ */

typedef struct {
    nodus_v2_gen_config_t *cfg;
    nodus_v2_gen_alloc_t  *allocs;
} cfgbox_t;

static void cfg_free(cfgbox_t *b)
{
    if (b) {
        free(b->cfg);
        free(b->allocs);
        memset(b, 0, sizeof(*b));
    }
}

static int cfg_make_v3_real(cfgbox_t *b, uint64_t genesis_time_ms)
{
    nodus_v2_gen_config_t *c;
    uint16_t k;

    memset(b, 0, sizeof(*b));
    b->cfg    = calloc(1, sizeof(*b->cfg));      /* ~240 KB: never stack  */
    b->allocs = calloc(1, sizeof(*b->allocs));
    if (!b->cfg || !b->allocs) {
        cfg_free(b);
        return -1;
    }
    c = b->cfg;
    c->config_version        = NODUS_V2_GEN_CONFIG_VERSION_V3;
    c->total_supply_raw      = DNAC_DEFAULT_TOTAL_SUPPLY;
    c->epoch_length          = (uint64_t)DNAC_EPOCH_LENGTH;
    c->blocks_per_year       = (uint64_t)DNAC_BLOCKS_PER_YEAR;
    c->decimal_unit          = (uint64_t)DNAC_DECIMAL_UNIT;
    c->inflation_start_block = 0ULL;   /* tokenomics-v3 P2: RETIRED,
                                        * the only legal value is 0 */
    c->claim_start_height    = 0;
    c->claim_end_height      = UINT64_MAX;
    c->n_validators          = (uint16_t)N_KEYS;
    for (k = 0; k < (uint16_t)N_KEYS; k++) {
        nodus_v2_gen_validator_t *v = &c->validators[k];
        size_t bb;

        memcpy(v->pubkey, g_ks[k].pk, DNAC_PUBKEY_SIZE);
        for (bb = 0; bb < DNAC_PUBKEY_SIZE; bb++) {
            v->unstake_destination_pubkey[bb] = (uint8_t)(v->pubkey[bb] ^ 0x5A);
        }
        hex_lower_fp(v->unstake_destination_pubkey, DNAC_PUBKEY_SIZE,
                     v->unstake_destination_fp);
        v->self_stake     = DNAC_SELF_STAKE_AMOUNT;
        v->commission_bps = (uint16_t)(100 * (k + 1));
    }
    memset(b->allocs[0].source_id, 0, sizeof(b->allocs[0].source_id));
    b->allocs[0].source_id[0] = 0x30;
    qgp_sha3_512(g_ks[0].pk, DNAC_PUBKEY_SIZE, b->allocs[0].dest_binding);
    b->allocs[0].amount = TREASURY_RAW;
    c->n_allocs = 1;
    c->allocs   = b->allocs;

    if (nodus_witness_v2_gen_v3_defaults(c) != 0) {
        cfg_free(b);
        return -1;
    }
    /* tokenomics-v3 P2 (P2-1): Rule P.2 now counts the reward reserve
     * (Σ allocs + Σ self_stake + reward_pool_initial == total). This
     * fixture's allocation already spends the whole supply, and it is not
     * a reward test — it reserves no pool (the reward path is
     * test_v2_econ's and the harness's). */
    c->reward_pool_initial = 0;
    c->genesis_time_ms = genesis_time_ms;
    c->initial_height  = 1;
    if (nodus_witness_v2_gen_v3_fill_comet_rows(c) != 0) {
        cfg_free(b);
        return -1;
    }
    return 0;
}

static void rmrf(const char *path)
{
    char cmd[300];

    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", path);
    if (system(cmd) != 0) { /* best effort */ }
}

typedef struct {
    nodus_server_t  *srv;
    nodus_witness_t *w;
    cfgbox_t         box;
    char             dir[128];
    uint8_t          chain32[32];
    /* second identity, admitted by hand into w->peers[] — never a real
     * socket ("HOW IT CAN LIE" (2)). */
    nodus_tcp_conn_t *peer1_conn;
} live_t;

/**
 * Derive a real 7-validator version-3 chain under a fresh temp directory
 * and bring up ONE live witness (validator 0's identity) through the REAL
 * `nodus_witness_init` path — `witness_post_open_gate`,
 * `nodus_witness_scan_chain_db`, `nodus_witness_peer_init` and, because
 * this chain IS version-3, `nodus_witness_cmt_live_init` all run for real.
 * R3 W4 deleted the auto-bootstrap state machine
 * (`nodus_witness_bootstrap_start`) that used to run between the scan and
 * the peer init: nothing replaces it (a pinned-successor node's joiner is
 * armed by `nodus_witness_v2_join_arm`, which this fixture's chain never
 * needs since `cfg_make_v3_real` derives the chain directly).
 * `witness->tcp` is left NULL
 * ("read how nodus_witness_tick tolerates it" — nodus_witness.c's
 * `if (witness->tcp)` guard) and `server->config.seed_count` is 0, so
 * `nodus_witness_peer_init`'s seed-dial loop never executes and no real
 * socket is ever opened by this fixture.
 */
static int live_open(live_t *L, const char *tag, uint64_t genesis_time_ms)
{
    nodus_witness_config_t wcfg;

    memset(L, 0, sizeof(*L));
    if (cfg_make_v3_real(&L->box, genesis_time_ms) != 0) {
        return -1;
    }
    if (nodus_witness_v2_gen_v3_validate(L->box.cfg) != 0) {
        return -1;
    }
    snprintf(L->dir, sizeof(L->dir), "/tmp/test_cmt_live_%s_XXXXXX", tag);
    if (!mkdtemp(L->dir)) {
        return -1;
    }
    if (nodus_witness_v2_gen_derive_v3(L->dir, L->box.cfg, L->chain32) != 0) {
        return -1;
    }

    L->srv = calloc(1, sizeof(*L->srv));         /* multi-MB: never stack */
    L->w   = calloc(1, sizeof(*L->w));
    if (!L->srv || !L->w) {
        return -1;
    }
    memcpy(L->srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(L->srv->identity.sk.bytes, g_ks[0].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(L->srv->identity.node_id.bytes, g_ks[0].voter, 32);
    snprintf(L->srv->config.data_path, sizeof(L->srv->config.data_path),
             "%s", L->dir);
    L->srv->config.seed_count = 0;
    /* w->tcp is left NULL (calloc'd) — deliberately, see this function's
     * doc comment; nodus_witness_peer_init casts it but never
     * dereferences it while seed_count is 0. */

    memset(&wcfg, 0, sizeof(wcfg));
    if (nodus_witness_init(L->w, L->srv, &wcfg) != 0) {
        return -1;
    }
    if (memcmp(L->w->v2_chain32, L->chain32, 32) != 0) {
        /* Would mean witness_post_open_gate accepted a DIFFERENT chain
         * than the one this fixture just derived — a fixture-detectable
         * fault, named here rather than surfacing later as a confusing
         * downstream mismatch. */
        return -1;
    }
    return 0;
}

/** Register g_ks[1] as roster witness 1 (for wsig verification inside
 *  nodus_witness_dispatch_t3) and as witness->peers[1] with a REAL,
 *  zeroed (state == NODUS_CONN_CLOSED) nodus_tcp_conn_t* — "HOW IT CAN
 *  LIE" (2). identified/conn are left UNSET here; the caller arms them
 *  at the point its case needs them "up". */
static int live_add_peer1(live_t *L)
{
    nodus_witness_roster_entry_t *e;

    if (L->w->roster.n_witnesses >= NODUS_T3_MAX_WITNESSES) return -1;
    e = &L->w->roster.witnesses[L->w->roster.n_witnesses++];
    memcpy(e->witness_id, g_ks[1].voter, NODUS_T3_WITNESS_ID_LEN);
    memcpy(e->pubkey, g_ks[1].pk, NODUS_PK_BYTES);
    e->active = true;

    L->peer1_conn = calloc(1, sizeof(*L->peer1_conn));
    if (!L->peer1_conn) return -1;
    /* Zero-init already leaves state == NODUS_CONN_CLOSED (value 0,
     * nodus_tcp.h:28) — no explicit assignment needed. Asserted here
     * rather than merely assumed, because this exact field is what
     * makes `net_send`'s eventual gossip attempt toward this dummy peer
     * fail cleanly instead of dereferencing garbage ("HOW IT CAN LIE"
     * (2)); a future field reorder that changed the zero value's meaning
     * must fail HERE, not as an unexplained crash deep in a reactor tick. */
    if (L->peer1_conn->state != NODUS_CONN_CLOSED) return -1;
    memcpy(L->w->peers[1].witness_id, g_ks[1].voter, NODUS_T3_WITNESS_ID_LEN);
    return 0;
}

/** Mark peers[1] "up" (net_slot_up's own predicate: conn != NULL &&
 *  identified) or clear it back down, WITHOUT touching peer_count (so
 *  nodus_witness_close's peer sweep, bounded by peer_count, never
 *  revisits this slot — "HOW IT CAN LIE" (2)). */
static void live_peer1_set_up(live_t *L, bool up)
{
    L->w->peers[1].conn       = up ? L->peer1_conn : NULL;
    L->w->peers[1].identified = up;
}

static void live_close(live_t *L)
{
    if (L->w) {
        nodus_witness_close(L->w);
    }
    free(L->peer1_conn);
    L->peer1_conn = NULL;
    free(L->w);
    L->w = NULL;
    free(L->srv);
    L->srv = NULL;
    cfg_free(&L->box);
    rmrf(L->dir);
}

/* ══ signed cometbft-envelope frame builder ══════════════════════════
 * Mirrors test_witness_protocol_version_gate.c's dispatch_prevote /
 * sign_prepared idiom, retargeted at the verb-35 (w_cmt_state) envelope
 * whose payload is a REAL marshalled NewRoundStep — test_cmt_net.c's
 * build_new_round_step, parameterised here by height so the version-gate
 * case can prove non-vacuously that a refused frame changed NOTHING. */
static int build_new_round_step_h(int64_t height, uint8_t *out, size_t cap,
                                  size_t *out_len)
{
    cmt_msg_t             msg;
    cmt_pb_cons_message_t pb;

    memset(&msg, 0, sizeof(msg));
    msg.kind                          = CMT_PB_CONS_MSG_NEW_ROUND_STEP;
    msg.u.new_round_step.height       = height;
    msg.u.new_round_step.round        = 0;
    msg.u.new_round_step.step         = CMT_ROUND_STEP_NEW_HEIGHT;
    msg.u.new_round_step.last_commit_round = 0;

    cmt_pb_cons_message_init(&pb);
    if (cmt_msg_to_proto(&msg, &pb) != CMT_OK) return -1;
    return cmt_pb_cons_message_marshal(&pb, out, cap, out_len) == CMT_OK
           ? 0 : -1;
}

/** Encode a signed w_cmt_state (verb 35) frame from `signer`'s identity
 *  at an arbitrary header `version`, carrying `body`/`body_len` as the
 *  opaque `w_cmt.m` bytes, and push it through the REAL
 *  `nodus_witness_dispatch_t3` — never `nodus_cmt_net_receive` directly. */
static void dispatch_cmt_state(nodus_witness_t *w, const keyset_t *signer,
                               uint8_t version, const uint8_t chain_id[32],
                               const uint8_t *body, size_t body_len)
{
    nodus_t3_msg_t m;
    nodus_seckey_t sk;
    static uint8_t buf[NODUS_T3_MAX_MSG_SIZE];
    size_t len = 0;

    memset(&m, 0, sizeof(m));
    m.type = NODUS_T3_CMT_STATE;
    m.txn_id = 1;
    m.header.version = version;
    m.header.round   = 0;
    m.header.view    = 0;
    memcpy(m.header.sender_id, signer->voter, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m.header.chain_id, chain_id, 32);
    m.header.timestamp = nodus_time_now();
    nodus_random((uint8_t *)&m.header.nonce, sizeof(m.header.nonce));
    m.w_cmt.m     = body;
    m.w_cmt.m_len = body_len;

    memcpy(sk.bytes, signer->sk, sizeof(sk.bytes));
    if (nodus_t3_encode(&m, &sk, buf, sizeof(buf), &len) != 0 || len == 0) {
        return; /* the caller's CHECK on the observed effect catches this */
    }
    /* conn == NULL: peer_ensure is conn-guarded
     * (nodus_witness.c:2803, "if (sender_idx >= 0 && conn)") — this
     * exercises the gate and the routing without a socket, the same
     * substitution test_witness_protocol_version_gate.c's
     * dispatch_prevote makes. */
    nodus_witness_dispatch_t3(w, NULL, buf, len);
}

/* ══ CASE 1 — genesis-time wait + the peer-admission gate ═══════════ */

static int t_genesis_wait_and_peer_gate(void)
{
    live_t   L;
    uint64_t gt;
    int      i;
    nodus_cmt_node_t *n;
    cmt_conr_t       *conr;
    cmt_memr_t       *memr;

    gt = now_ms() + GENESIS_LEAD_MS;
    CHECK(live_open(&L, "gwait", gt) == 0, "one live validator, chain in "
          "the near future");
    CHECK(live_add_peer1(&L) == 0, "second identity registered");

    n    = (nodus_cmt_node_t *)L.w->cmt_node;
    conr = (cmt_conr_t *)L.w->cmt_conr;
    memr = (cmt_memr_t *)L.w->cmt_memr;
    CHECK(n && conr && memr, "the startup table and both reactors were "
          "built at init — cmt_live gates STARTING them, not building "
          "them (nodus_witness.c:1556-1560)");

    CHECK(L.w->cmt_live == false, "cmt_live starts false");
    CHECK(conr->running == false && memr->running == false,
          "and neither reactor is running yet");

    /* (1b) mark the peer "up" BEFORE the reactors run. */
    live_peer1_set_up(&L, true);

    /* This file's OWN setup (live_open + live_add_peer1, above) must not
     * have already eaten the whole GENESIS_LEAD_MS lead — if it has, the
     * loop below runs ZERO times and 1a/1b are never actually observed,
     * a silent vacuity rather than a failure ("HOW IT CAN LIE" (4)). Made
     * a hard, visible CHECK rather than an implicit assumption. */
    CHECK(now_ms() < gt, "genesis_time is still ahead of us after setup — "
          "GENESIS_LEAD_MS has margin left to observe the BEFORE state");

    /* Tick a few times while genesis_time is still in the future: the
     * tick must be a no-op for BOTH the lane and the peer set. Progress
     * is expressed as "still before gt", never a fixed iteration count
     * alone — the loop also bounds itself so a clock or arithmetic
     * defect cannot spin forever. */
    for (i = 0; i < WAIT_TICKS_MAX && now_ms() < gt; i++) {
        CHECK(L.w->running, "the node has not halted while waiting");
        nodus_witness_tick(L.w);
        CHECK(L.w->cmt_live == false, "cmt_live stays false before "
              "genesis_time");
        CHECK(conr->peers[1].in_set == false, "a peer marked up before "
              "both reactors run is NOT admitted "
              "(nodus_witness_cmt_net.c:519)");
        usleep(TICK_SLEEP_US);
    }
    CHECK(i > 0, "the before-genesis loop actually ran at least once — "
          "not a silent zero-iteration pass");
    CHECK(now_ms() >= gt, "the wait loop actually reached genesis_time "
          "(WAIT_TICKS_MAX did not expire first — GENESIS_LEAD_MS vs "
          "this file's own setup cost, HOW IT CAN LIE (4))");

    /* (1c) — cross genesis_time; the wait for cmt_live itself is a
     * SEPARATE bounded loop so a slow flip is distinguishable from a
     * halted node. */
    for (i = 0; i < WAIT_TICKS_MAX && !L.w->cmt_live; i++) {
        CHECK(L.w->running, "node halted (CMT_FAULT) while starting the "
              "cometbft lane — distinct from \"still waiting\"");
        nodus_witness_tick(L.w);
        usleep(TICK_SLEEP_US);
    }
    CHECK(L.w->cmt_live == true, "the tick started the cometbft lane "
          "once genesis_time was reached");
    CHECK(conr->running && memr->running, "both reactors are running");
    CHECK(n->cs_started == true, "and cmt_conr_start actually reached "
          "cmt_cs_start (the caller-set contract, "
          "nodus_witness_cmt_node.h)");
    /* (1c continued) — witness_cmt_tick's (b)(c)(d) run UNCONDITIONALLY
     * right after the genesis-time block, with no `return` between them
     * (nodus_witness.c:1611-1698): the SAME tick call that just started
     * both reactors also fell through into the peer-set scan, so the
     * slot marked up before the wait began is ALREADY admitted — no
     * further tick was needed for admission itself. */
    CHECK(conr->peers[1].in_set == true, "the peer is admitted in the "
          "SAME tick that starts both reactors, no retry logic needed");

    /* (1d) — one further tick, nothing about the slot changed: proves
     * the scan is idempotent for an unchanged "up" slot (re-scanning
     * never re-adds or drops it, nodus_witness_cmt_net.c:527-533). */
    nodus_witness_tick(L.w);
    CHECK(conr->peers[1].in_set == true, "still admitted after an "
          "unrelated tick");

    /* (1e) — clear it; the down transition removes it again. */
    live_peer1_set_up(&L, false);
    nodus_witness_tick(L.w);
    CHECK(conr->peers[1].in_set == false, "and removed on the down "
          "transition");

    fprintf(stderr, "  recv_arena_used=%zu\n",
            nodus_cmt_net_recv_arena_used((nodus_cmt_net_t *)L.w->cmt_net));
    live_close(&L);
    return 0;
}

/* ══ CASE 2 — the version gate for verb 35, through the REAL dispatcher ═ */

static int t_version_gate_verb35(void)
{
    live_t   L;
    int      i;
    cmt_conr_t *conr;
    uint8_t  body5[512], body6[512], body7[512];
    size_t   len5 = 0, len6 = 0, len7 = 0;
    cmt_prs_t prs;

    /* genesis in the past: this case needs the lane live, not the wait. */
    CHECK(live_open(&L, "vgate", now_ms() - 5000) == 0,
          "one live validator, chain already past genesis_time");
    /* ORCHESTRATOR delta 3 — `witness->last_epoch` starts at 0, so the
     * VERY FIRST tick's `witness_mesh_tick` (nodus_witness.c:2379-2430,
     * run before `witness_cmt_tick` on a version-3 chain since the C2a
     * tick fix) sees `now - 0 >= WITNESS_EPOCH_SECS` and rebuilds
     * `witness->roster` from the (empty, in this fixture) DHT peer
     * registry, REPLACING it wholesale (`round_state.phase` is IDLE, the
     * only branch this lane ever takes) — wiping the hand-registered
     * `g_ks[1]` entry `live_add_peer1` just added before this case's own
     * dispatch ever runs. Priming `last_epoch` to "now" holds the 60 s
     * refresh off for the whole bounded window below; the refresh itself
     * is NOT what this case measures — see "HOW IT CAN LIE". */
    L.w->last_epoch = nodus_time_now();
    CHECK(live_add_peer1(&L) == 0, "second identity registered");
    live_peer1_set_up(&L, true);

    conr = (cmt_conr_t *)L.w->cmt_conr;
    for (i = 0; i < WAIT_TICKS_MAX && !L.w->cmt_live; i++) {
        CHECK(L.w->running, "node halted while starting the lane");
        nodus_witness_tick(L.w);
        usleep(TICK_SLEEP_US);
    }
    CHECK(L.w->cmt_live, "the lane is live (genesis_time is in the past)");
    /* The tick that started the lane also fell through into the peer-set
     * scan in the SAME call (nodus_witness.c:1611-1698, no `return`
     * between the genesis-time block and the scan) — peers[1] was
     * already marked up, so it is admitted by now. One more tick proves
     * that is stable, not a transient race. */
    nodus_witness_tick(L.w);
    CHECK(conr->peers[1].in_set, "the second identity is admitted");

    /* PRECONDITION, named so a future change that makes the epoch
     * refresh fire again fails HERE, by name, not at the round-state
     * line below — see the `last_epoch` priming above and "HOW IT CAN
     * LIE". `nodus_witness_dispatch_t3`'s roster lookup
     * (`nodus_witness_roster_find`) runs BEFORE the version gate; a
     * wiped roster would make every dispatch below "from unknown
     * sender, ignoring" (nodus_witness.c:2693-2698), never reaching the
     * version check it is meant to prove. */
    {
        int found = 0;
        uint32_t k;

        for (k = 0; k < L.w->roster.n_witnesses; k++) {
            if (memcmp(L.w->roster.witnesses[k].witness_id, g_ks[1].voter,
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                found = 1;
                break;
            }
        }
        CHECK(found, "witness->roster still carries the second identity "
              "after ticking — the epoch refresh did not fire and wipe it");
    }

    /* Three DISTINCT heights so a wrongly-accepted frame is
     * OBSERVABLE — see this file's "HOW IT CAN LIE" and the CASE 2 doc
     * comment: non-vacuity means the wrong-version attempts must be
     * ABLE to move the peer's state and provably do not. */
    CHECK(build_new_round_step_h(5, body5, sizeof(body5), &len5) == 0,
          "height-5 NewRoundStep (the version-7 frame)");
    CHECK(build_new_round_step_h(6, body6, sizeof(body6), &len6) == 0,
          "height-6 NewRoundStep (the version-6 frame)");
    CHECK(build_new_round_step_h(7, body7, sizeof(body7), &len7) == 0,
          "height-7 NewRoundStep (the version-8 frame)");

    /* ACCEPT at version 7. */
    dispatch_cmt_state(L.w, &g_ks[1], NODUS_T3_BFT_PROTOCOL_VER,
                       L.chain32, body5, len5);
    cmt_ps_get_round_state(&conr->peers[1].ps, &prs);
    CHECK(prs.height == 5 && prs.round == 0, "version 7 is ACCEPTED — the "
          "peer's own round state now reads height 5 / round 0");

    /* REFUSE at version 6 — the shipped legacy value, one below current. */
    dispatch_cmt_state(L.w, &g_ks[1], (uint8_t)(NODUS_T3_BFT_PROTOCOL_VER - 1),
                       L.chain32, body6, len6);
    cmt_ps_get_round_state(&conr->peers[1].ps, &prs);
    CHECK(prs.height == 5 && prs.round == 0, "version 6 is REFUSED — the "
          "peer's round state did NOT move to height 6");

    /* REFUSE at version 8 — an unknown NEWER value. */
    dispatch_cmt_state(L.w, &g_ks[1], (uint8_t)(NODUS_T3_BFT_PROTOCOL_VER + 1),
                       L.chain32, body7, len7);
    cmt_ps_get_round_state(&conr->peers[1].ps, &prs);
    CHECK(prs.height == 5 && prs.round == 0, "version 8 is REFUSED — the "
          "peer's round state did NOT move to height 7");

    /* Remove the peer, as the dispatch's own narrative closes this case. */
    live_peer1_set_up(&L, false);
    nodus_witness_tick(L.w);
    CHECK(conr->peers[1].in_set == false, "removed");

    fprintf(stderr, "  recv_arena_used=%zu\n",
            nodus_cmt_net_recv_arena_used((nodus_cmt_net_t *)L.w->cmt_net));
    live_close(&L);
    return 0;
}

/* ══ CASE 3 — CheckTx: a genesis-funded claim, and a forged copy ════════
 *
 * Builds `dna_claim_t` exactly as test_cmt_app.c's claim cases do
 * (:2378-2448): the ONE distribution leaf this chain's genesis document
 * carries (allocs[0], bound to validator 0's pubkey, TREASURY_RAW),
 * signed by validator 0's OWN key — the funded, admissible case — and
 * the SAME fields signed by validator 1's key instead, which
 * `nodus_witness_v2_claim_admit`'s signature check must refuse. Submitted
 * through the LIVE node's own `n->mem` (cmt_mem_check_tx), not a bare
 * `cmt_mem_app_t` row — the mempool the startup table actually built. */
static int t_checktx_funded_and_forged(void)
{
    live_t   L;
    nodus_cmt_node_t *n;
    dna_gman_t        m;
    dna_dist_leaf_t   leaf;
    uint8_t           mh[64], leaf_hash[64];
    dna_claim_t      *good, *bad;
    uint8_t          *cbytes, *bbytes;
    size_t            clen = 0, blen = 0;
    cmt_mem_tx_info_t info;
    cmt_mem_response_check_tx_t res;
    cmt_mem_error_t   err;

    CHECK(live_open(&L, "checktx", now_ms() - 5000) == 0,
          "one live validator, chain already past genesis_time");
    n = (nodus_cmt_node_t *)L.w->cmt_node;
    CHECK(n && n->mem, "the startup table built the real mempool");

    CHECK(nodus_witness_v2_manifest_load(L.w, 0, &m) == 0,
          "the genesis manifest is committed at seq 0");
    CHECK(dna_gman_hash(&m, mh) == 0, "its hash");
    CHECK(m.dist_present == 1, "it carries a distribution section");

    memset(&leaf, 0, sizeof(leaf));
    leaf.leaf_version   = DNA_DIST_VERSION;
    leaf.source_id_len  = (uint16_t)NODUS_V2_GEN_SRCID_LEN;
    memcpy(leaf.source_id, L.box.allocs[0].source_id, NODUS_V2_GEN_SRCID_LEN);
    leaf.source_amount  = L.box.allocs[0].amount;
    memcpy(leaf.dest_binding, L.box.allocs[0].dest_binding, 64);
    CHECK(dna_dist_leaf_hash(&leaf, leaf_hash) == 0, "leaf hash");

    good = calloc(1, sizeof(*good));   /* ~5 KB each: never on the stack */
    bad  = calloc(1, sizeof(*bad));
    cbytes = malloc(DNA_CLAIM_MAX_WIRE);
    bbytes = malloc(DNA_CLAIM_MAX_WIRE);
    CHECK(good && bad && cbytes && bbytes, "alloc");

    good->claim_version = DNA_CLAIM_VERSION;
    memcpy(good->chain_id, L.chain32, DNA_CHAIN_ID_LEN);
    memcpy(good->manifest_hash, mh, 64);
    good->leaf_index    = 0;
    good->source_id_len = leaf.source_id_len;
    memcpy(good->source_id, leaf.source_id, leaf.source_id_len);
    good->source_amount = leaf.source_amount;
    memcpy(good->dest_binding, leaf.dest_binding, 64);
    good->n_siblings = 0;             /* a one-leaf tree */
    good->auth_mode  = DNA_CLAIMAUTH_DNA_NATIVE;
    memcpy(good->pubkey, g_ks[0].pk, QGP_DSA87_PUBLICKEYBYTES);
    {
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t  pre_len = 0, siglen = 0;

        CHECK(dna_claim_preimage(good, pre, &pre_len) == 0, "preimage");
        CHECK(qgp_dsa87_sign(good->signature, &siglen, pre, pre_len,
                             g_ks[0].sk) == 0 &&
              siglen == DNA_CLAIM_SIG_LEN,
              "the funded claimant (validator 0) signs it");
    }
    CHECK(dna_claim_encode(good, cbytes, DNA_CLAIM_MAX_WIRE, &clen) == 0,
          "the funded claim encodes");

    /* the IDENTICAL fields, signed by a DIFFERENT validator's key —
     * a wrong-signature copy, not a different claim. */
    memcpy(bad, good, sizeof(*bad));
    {
        uint8_t pre[DNA_CLAIM_PREIMAGE_MAX];
        size_t  pre_len = 0, siglen = 0;

        CHECK(dna_claim_preimage(bad, pre, &pre_len) == 0, "preimage "
              "(identical fields, including the pubkey the good claim "
              "carries)");
        CHECK(qgp_dsa87_sign(bad->signature, &siglen, pre, pre_len,
                             g_ks[1].sk) == 0, "signed with the WRONG key");
    }
    CHECK(dna_claim_encode(bad, bbytes, DNA_CLAIM_MAX_WIRE, &blen) == 0,
          "it encodes too — refused at authorization, not at decode");

    /* PRECONDITION, named so a refusal here explains itself rather than
     * surfacing as a confusing "funded claim was refused" below. Both
     * CheckTx calls route through nodus_cmt_app_check_tx ->
     * nodus_witness_verify_transaction -> the successor divert
     * (nodus_witness_verify.c:808-813) -> verify_v2_successor_tx, whose
     * FIRST gate is `nodus_witness_v2_ingress_is_armed` (:653-657) —
     * BEFORE any claim/signature work runs at all. Ingress is armed at
     * open (`witness_post_open_gate`) only when the ACTIVATION PREFLIGHT
     * accepts the chain; in this worktree that preflight is the
     * PRE-C2c one (S10-S12 only), which reports SCHEMA_UNSUPPORTED for
     * a version-3 (S14) chain and never arms — package C2c (a sibling
     * worktree) rewrites the preflight against S14 and the genesis
     * document. This CHECK is therefore expected to be RED here and
     * GREEN once C2c lands; without it, a closed gate would refuse BOTH
     * the funded and the forged claim identically, and the "forged
     * claim is refused" assertion below would be a vacuous pass — see
     * "HOW IT CAN LIE" (7). */
    CHECK(nodus_witness_v2_ingress_is_armed(L.w) == 1,
          "the activation gate armed at open — the preflight must accept "
          "a version-3 chain (package C2c); RED on the pre-C2c preflight, "
          "expected GREEN in the integrated tree");

    memset(&info, 0, sizeof(info));
    memset(&res, 0, sizeof(res));
    cmt_mem_error_init(&err);
    CHECK(cmt_mem_check_tx(n->mem, cbytes, clen, &info, &res, &err) == CMT_OK,
          "the funded claim is served by the live mempool");
    fprintf(stderr, "  funded claim: res.code=%u gas_wanted=%" PRId64
            " gas_used=%" PRId64 "\n", res.code, res.gas_wanted,
            res.gas_used);
    CHECK(res.code == CMT_MEM_CODE_TYPE_OK, "and admitted AT ONCE");

    memset(&res, 0, sizeof(res));
    cmt_mem_error_init(&err);
    CHECK(cmt_mem_check_tx(n->mem, bbytes, blen, &info, &res, &err) == CMT_OK,
          "the forged claim is also served");
    fprintf(stderr, "  forged claim: res.code=%u gas_wanted=%" PRId64
            " gas_used=%" PRId64 "\n", res.code, res.gas_wanted,
            res.gas_used);
    CHECK(res.code != CMT_MEM_CODE_TYPE_OK, "and REFUSED — "
          "nodus_witness_v2_claim_admit's signature check "
          "(nodus_witness_verify.c:531-615)");

    free(bbytes);
    free(cbytes);
    free(bad);
    free(good);

    fprintf(stderr, "  recv_arena_used=%zu\n",
            nodus_cmt_net_recv_arena_used((nodus_cmt_net_t *)L.w->cmt_net));
    live_close(&L);
    return 0;
}

/* ══ CASE 4 — restart reopens the SAME role over the SAME chain ═══════ */

static int t_restart_reopens_same_role(void)
{
    live_t   L;
    uint8_t  chain_before[32];
    nodus_witness_config_t wcfg;

    CHECK(live_open(&L, "restart", now_ms() - 5000) == 0,
          "one live validator, chain already past genesis_time");
    memcpy(chain_before, L.w->v2_chain32, 32);
    CHECK(L.w->v2_successor, "this node holds a version-3 chain");
    CHECK(L.w->cmt_node && L.w->cmt_net, "the startup table is live");

    nodus_witness_close(L.w);
    /* nodus_witness_init re-memsets *witness (nodus_witness.c:1710) —
     * safe to reuse the same heap object; the server (identity,
     * config.data_path) is untouched by close. */
    memset(&wcfg, 0, sizeof(wcfg));
    CHECK(nodus_witness_init(L.w, L.srv, &wcfg) == 0,
          "the SAME server, over the SAME data directory, re-inits");
    CHECK(L.w->v2_successor, "the chain role is rediscovered as "
          "version-3, not lost across the restart");
    CHECK(memcmp(L.w->v2_chain32, chain_before, 32) == 0,
          "and it is the SAME chain id — "
          "witness_post_open_gate re-derived it from the SAME stored "
          "genesis document, not a fresh one");
    CHECK(L.w->cmt_node && L.w->cmt_net && L.w->cmt_conr && L.w->cmt_memr,
          "the cometbft server binding is rebuilt");
    /* BLOCKED, named rather than asserted (file header, HOW IT CAN LIE):
     * no block ever committed in this process's first life, so there is
     * no tip for production to resume PAST. This proves the restart does
     * not corrupt or refuse the chain — not that it resumes production. */

    fprintf(stderr, "  recv_arena_used=%zu\n",
            nodus_cmt_net_recv_arena_used((nodus_cmt_net_t *)L.w->cmt_net));
    live_close(&L);
    return 0;
}

/* ══ CASE 5 — mesh maintenance must run on a version-3 chain too ═══════
 *
 * ORCHESTRATOR delta 2. Was RED against the tick body of that delta
 * (`if (witness->v2_successor) { ... witness_cmt_tick(...); return; }`,
 * unconditional and BEFORE `nodus_witness_peer_tick` or the 60 s roster
 * refresh were ever reached). Delta 3: the C2a writer's fix landed —
 * `nodus_witness_tick` now calls `witness_mesh_tick` (nodus_witness.c:
 * 2379-2430: `nodus_witness_peer_tick` then the epoch roster refresh)
 * BEFORE `witness_cmt_tick` on a version-3 chain (call site :2502-2504)
 * — and this case is GREEN against it. It found a SECOND live-node
 * defect as a side effect of proving the first one fixed: see delta 3's
 * `last_epoch` priming and the roster precondition below, and this
 * file's "HOW IT CAN LIE".
 *
 * UNLIKE EVERY OTHER CASE IN THIS FILE, this one needs a REAL
 * `nodus_tcp_t` on `witness->tcp`: `nodus_witness_peer_tick`'s reconnect
 * loop calls `nodus_tcp_connect(wtcp, ip, port)`
 * (nodus_witness_peer.c:1765), which returns NULL at once for a NULL
 * transport (`nodus_tcp_connect`'s own guard, nodus_tcp.c:883) — every
 * other case leaves `witness->tcp` NULL because it never needs this
 * path. `nodus_tcp_init(&tcp, -1)` builds a standalone, self-managed
 * transport (its own `epoll_create1`, `owns_epoll = true`,
 * nodus_tcp.c:820-827) — the same idiom `test_tcp.c` uses, no server
 * required — and `nodus_witness_tick`'s own unconditional `if
 * (witness->tcp) nodus_tcp_poll(...)` (nodus_witness.c:2342-2343, which
 * runs on EVERY tick, before the version-3 branch) drives it.
 */
static int t_mesh_ticks_on_v3(void)
{
    live_t      L;
    nodus_tcp_t tcp;
    int         i, idx;

    CHECK(live_open(&L, "meshtick", now_ms() - 5000) == 0,
          "one live validator, chain already past genesis_time");
    /* ORCHESTRATOR delta 3 — the SAME `witness_mesh_tick` this case
     * exists to prove ALSO runs the 60 s epoch roster refresh right
     * after `nodus_witness_peer_tick` (nodus_witness.c:2379-2430), and
     * `witness->last_epoch` starts at 0, so the refresh fires on the
     * very first tick and REPLACES `witness->roster` wholesale with
     * whatever `nodus_witness_rebuild_roster_from_peers` derives from
     * the (empty, in this fixture) DHT peer registry. Without priming
     * this, the hand-registered `g_ks[1]` roster entry below survives
     * only because `nodus_witness_peer_tick` happens to run FIRST inside
     * `witness_mesh_tick` and dials it before the SAME call's refresh
     * wipes the roster — an ORDER dependency, not a property this case
     * is meant to test. Priming `last_epoch` to "now" holds the refresh
     * off for the whole bounded window below. */
    L.w->last_epoch = nodus_time_now();
    CHECK(nodus_tcp_init(&tcp, -1) == 0,
          "a standalone witness transport (self-managed epoll)");
    L.w->tcp = &tcp;

    /* A SECOND genesis witness (g_ks[1], not self — `w->my_id` excludes
     * self by witness_id, nodus_witness_peer.c:1723-1725), registered in
     * the roster with an address that is syntactically valid
     * (`parse_address` needs "IP:PORT", nodus_witness_peer.c:71-89) but
     * unreachable: loopback, a low port nothing listens on. A refused
     * loopback connection returns an IMMEDIATE RST on this OS — this
     * cannot hang the tick (see this case's "HOW IT CAN LIE" note, file
     * header item 8), and the assertion below does not even depend on
     * the refusal ever being observed: `last_attempt` is set the moment
     * the non-blocking connect is QUEUED (nodus_witness_peer.c:1788),
     * synchronously inside the SAME tick call. */
    {
        nodus_witness_roster_entry_t *e =
            &L.w->roster.witnesses[L.w->roster.n_witnesses++];

        memset(e, 0, sizeof(*e));
        memcpy(e->witness_id, g_ks[1].voter, NODUS_T3_WITNESS_ID_LEN);
        memcpy(e->pubkey, g_ks[1].pk, NODUS_PK_BYTES);
        snprintf(e->address, sizeof(e->address), "127.0.0.1:1");
        e->active = true;
    }

    /* find_peer_by_id is static (nodus_witness_peer.c:94) — read
     * witness->peers[] directly, the same scan, bounded by peer_count. */
    idx = -1;
    for (i = 0; i < WAIT_TICKS_MAX && idx < 0; i++) {
        int j;

        CHECK(L.w->running, "the node has not halted");
        nodus_witness_tick(L.w);
        for (j = 0; j < L.w->peer_count; j++) {
            if (memcmp(L.w->peers[j].witness_id, g_ks[1].voter,
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                idx = j;
                break;
            }
        }
        if (idx < 0) {
            usleep(TICK_SLEEP_US);
        }
    }
    CHECK(idx >= 0, "nodus_witness_peer_tick ran and created a peer table "
          "entry for the roster witness (nodus_witness.c:2502-2504 calls "
          "witness_mesh_tick, which calls nodus_witness_peer_tick, on a "
          "version-3 chain — the ORCHESTRATOR's C2a fix for the defect "
          "this case exists to catch)");
    CHECK(L.w->peers[idx].last_attempt != 0, "and it actually ATTEMPTED "
          "the dial (last_attempt is set right after nodus_tcp_connect "
          "queued the connection, nodus_witness_peer.c:1788) — not "
          "merely a roster-derived placeholder entry with nothing done");

    /* PRECONDITION, so this case no longer depends on peer_tick running
     * BEFORE the epoch refresh inside the same witness_mesh_tick call —
     * see the `last_epoch` priming above and "HOW IT CAN LIE". */
    {
        int found = 0;
        uint32_t k;

        for (k = 0; k < L.w->roster.n_witnesses; k++) {
            if (memcmp(L.w->roster.witnesses[k].witness_id, g_ks[1].voter,
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                found = 1;
                break;
            }
        }
        CHECK(found, "witness->roster still carries the second identity "
              "after the whole tick loop — the epoch refresh did not "
              "fire and wipe it");
    }

    L.w->tcp = NULL;
    nodus_tcp_close(&tcp);

    fprintf(stderr, "  recv_arena_used=%zu\n",
            nodus_cmt_net_recv_arena_used((nodus_cmt_net_t *)L.w->cmt_net));
    live_close(&L);
    return 0;
}

/* ══ CASE 6 — R3-W3-C2a-18: adoption mid-life must go live, not just hold
 *    the role ══════════════════════════════════════════════════════════ */

/**
 * ORCHESTRATOR delta 10 (R3-W3-C2a-18) — a LIVE DEFECT the third Genesis
 * Protocol sweep found (`test_v2_join.sh`, node 6 wiped and restarted with
 * only the pin): a joiner that receives and adopts a genesis bundle
 * mid-life NEVER goes live. `join_adopt` (nodus_witness_v2_join.c) runs
 * `nodus_witness_scan_chain_db(w)` on the LIVE witness, which sets
 * `v2_successor`/`v2_chain32` through the SAME `witness_post_open_gate`
 * every restart runs — but nothing built the cometbft startup table or
 * transport glue afterward, so `witness_cmt_tick` returned INT64_MAX
 * forever (`cmt_node == NULL`) and the node held the role, printed "chain
 * role: COMETBFT", and never ran consensus or caught up (there is no
 * blocksync in this port — catch-up IS the reactor's own stored-part
 * gossip, which needs the reactor). Delta 10's fix EXPORTS the
 * constructor (`witness_cmt_live_init` -> `nodus_witness_cmt_live_init`,
 * nodus_witness.c/.h) so `join_adopt` can call it a second way, the same
 * one `nodus_witness_init` already calls at process start; C2c's own
 * follow-up delta wires that call inside join.c (outside this package's
 * whitelist, not done here).
 *
 * This case does NOT drive `join_adopt` itself (that needs a genesis
 * bundle transfer between two live processes, C2c/C2d's ground) — it
 * reproduces the exact SEQUENCE `join_adopt` puts a witness through and
 * proves the EXPORTED function closes the gap: `nodus_witness_init` on a
 * genuinely PRE-GENESIS data directory (no chain file at all — the same
 * state a fresh joiner starts in, `v2_successor` stays false, no
 * cometbft construction runs), THEN a real v3 chain derived directly
 * into that SAME data directory (mirroring `join_adopt`'s rename of its
 * scratch DB into `w->data_path`, nodus_witness_v2_join.c:174), THEN the
 * SAME scan `join_adopt` calls (nodus_witness_v2_join.c:187) — which
 * adopts the role but (confirmed here, this is the defect) leaves all
 * four cometbft pointers NULL — THEN the exported constructor itself,
 * THEN a bounded tick loop past genesis time proving the lane actually
 * goes LIVE, THEN a second call proving the entry guard (delta 8, item
 * C) refuses without disturbing anything already built.
 *
 * RED-BEFORE-THIS-DELTA, STATED HONESTLY: before delta 10,
 * `nodus_witness_cmt_live_init` did not exist as a callable symbol from
 * this file — `witness_cmt_live_init` was `static` to nodus_witness.c.
 * The RED this case is against is the ABSENCE of the exported function
 * (this file would not compile), not a behavioural failure of a function
 * that already existed — inventing a "the old code returns X" RED here
 * would be false: there was no way to call it from outside its own file
 * to observe any return value at all.
 */
static int t_adopt_then_live(void)
{
    live_t                  L;
    nodus_witness_config_t  wcfg;
    void                   *pn, *pne, *pc, *pm;
    int                     i;

    char scratch[256];

    memset(&L, 0, sizeof(L));
    CHECK(cfg_make_v3_real(&L.box, now_ms() + GENESIS_LEAD_MS) == 0,
          "config");
    CHECK(nodus_witness_v2_gen_v3_validate(L.box.cfg) == 0, "validate");
    snprintf(L.dir, sizeof(L.dir), "/tmp/test_cmt_live_adopt_XXXXXX");
    CHECK(mkdtemp(L.dir) != NULL, "mkdtemp");

    /* ORCHESTRATOR (integration of delta 10): the writer's first shape
     * started the witness on an empty dir with NO pin and then derived
     * into it; that never reaches the joiner's branch — a pin-less
     * pre-genesis node takes the legacy DISCOVER path and its C-1 seed
     * gate refuses init at seed_count 0 (measured: "C-1 gate FAIL —
     * seed_count=0 < committee_size=7"). The harness's joiner is PINNED,
     * so it takes nodus_witness_bootstrap.c's V2_PINNED_JOINER branch
     * instead. Mirror the joiner exactly: derive in a SCRATCH dir first
     * (the chain id IS the pin), start the witness pinned on an EMPTY
     * data dir, then rename the derived database into the data dir the
     * way join_adopt does (nodus_witness_v2_join.c:181-194), then scan. */
    snprintf(scratch, sizeof(scratch), "/tmp/test_cmt_live_adoptS_XXXXXX");
    CHECK(mkdtemp(scratch) != NULL, "mkdtemp scratch");
    CHECK(nodus_witness_v2_gen_derive_v3(scratch, L.box.cfg, L.chain32) == 0,
          "derive v3 into a scratch dir (the joiner's provisional chain)");

    L.srv = calloc(1, sizeof(*L.srv));
    L.w   = calloc(1, sizeof(*L.w));
    CHECK(L.srv && L.w, "alloc");
    memcpy(L.srv->identity.pk.bytes, g_ks[0].pk, NODUS_PK_BYTES);
    memcpy(L.srv->identity.sk.bytes, g_ks[0].sk, QGP_DSA87_SECRETKEYBYTES);
    memcpy(L.srv->identity.node_id.bytes, g_ks[0].voter, 32);
    snprintf(L.srv->config.data_path, sizeof(L.srv->config.data_path),
             "%s", L.dir);
    L.srv->config.seed_count = 0;
    L.srv->config.has_v2_genesis_pin = true;      /* the joiner's anchor */
    memcpy(L.srv->config.v2_genesis_pin, L.chain32, 32);

    /* (1) init on a genuinely PRE-GENESIS data dir — no chain file yet,
     * the same state a fresh PINNED joiner starts life in. */
    memset(&wcfg, 0, sizeof(wcfg));
    CHECK(nodus_witness_init(L.w, L.srv, &wcfg) == 0,
          "pre-genesis init on the PINNED joiner branch");
    CHECK(!L.w->v2_successor, "no chain adopted yet — no role");
    CHECK(L.w->cmt_node == NULL, "no startup table built yet");

    /* (2) adopt by RENAME into the data directory — join_adopt's own
     * step (nodus_witness_v2_join.c:181-194), byte for byte the same
     * filename rule (the chain id's first 16 bytes as hex). */
    {
        char hex[33], from[512], to[512];
        int  k;
        for (k = 0; k < 16; k++)
            snprintf(hex + k * 2, 3, "%02x", L.chain32[k]);
        snprintf(from, sizeof(from), "%s/witness_%s.db", scratch, hex);
        snprintf(to,   sizeof(to),   "%s/witness_%s.db", L.dir,   hex);
        CHECK(rename(from, to) == 0,
              "adopt by rename into the data dir (join_adopt's own step)");
        rmrf(scratch);
    }

    /* (3) the SAME scan join_adopt calls (nodus_witness_v2_join.c:187) —
     * adopts the role through the SAME post-open gate every restart
     * runs. This is where the defect lived: role set, nothing built. */
    CHECK(nodus_witness_scan_chain_db(L.w) == 0, "scan adopts the chain");
    L.w->v2_join.active = 0;                     /* as join_adopt does */
    CHECK(L.w->v2_successor, "role set by the SAME post-open gate a "
          "restart would run");
    CHECK(memcmp(L.w->v2_chain32, L.chain32, 32) == 0,
          "and it is the right chain id");
    CHECK(L.w->cmt_node == NULL && L.w->cmt_net == NULL &&
          L.w->cmt_conr == NULL && L.w->cmt_memr == NULL,
          "THE DEFECT, reproduced: role held, nothing built yet — this "
          "is exactly the harness's \"role=1 live=0\" state");

    /* (4) the exported constructor — what join_adopt's own follow-up
     * delta must call immediately after its scan. */
    CHECK(nodus_witness_cmt_live_init(L.w) == 0,
          "the exported constructor builds the four");
    pn = L.w->cmt_node; pne = L.w->cmt_net;
    pc = L.w->cmt_conr; pm = L.w->cmt_memr;
    CHECK(pn && pne && pc && pm, "all four pointers now populated");
    CHECK(!L.w->cmt_live, "not live yet — genesis time not reached");

    /* (5) tick past genesis time — the SAME transition
     * t_genesis_wait_and_peer_gate exercises after nodus_witness_init's
     * OWN call to this constructor; here it follows the SECOND caller. */
    for (i = 0; i < WAIT_TICKS_MAX && !L.w->cmt_live; i++) {
        CHECK(L.w->running, "the node has not halted while waiting");
        nodus_witness_tick(L.w);
        if (!L.w->cmt_live) {
            usleep(TICK_SLEEP_US);
        }
    }
    CHECK(L.w->cmt_live, "the lane went LIVE after mid-life adoption — "
          "the defect this case exists to catch is closed");

    /* (6) the entry guard (delta 8, item C) refuses a second call and
     * disturbs nothing already built. */
    CHECK(nodus_witness_cmt_live_init(L.w) == -1,
          "a second call over an existing construction is refused");
    CHECK(L.w->cmt_node == pn && L.w->cmt_net == pne &&
          L.w->cmt_conr == pc && L.w->cmt_memr == pm,
          "and none of the four pointers were rebuilt or leaked");

    fprintf(stderr, "  recv_arena_used=%zu\n",
            nodus_cmt_net_recv_arena_used((nodus_cmt_net_t *)L.w->cmt_net));
    live_close(&L);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════ */

int main(void)
{
    struct { const char *name; int (*fn)(void); } cases[] = {
        { "genesis_wait_and_peer_gate",   t_genesis_wait_and_peer_gate   },
        { "version_gate_verb35",          t_version_gate_verb35          },
        { "checktx_funded_and_forged",    t_checktx_funded_and_forged    },
        { "restart_reopens_same_role",    t_restart_reopens_same_role    },
        { "mesh_ticks_on_v3",             t_mesh_ticks_on_v3             },
        { "adopt_then_live",              t_adopt_then_live              },
    };
    size_t i, failed = 0, ncases = sizeof(cases) / sizeof(cases[0]);

    if (make_keys() != 0) {
        fprintf(stderr, "test_cmt_live: key generation failed\n");
        return 1;
    }

    fprintf(stderr,
            "test_cmt_live: BLOCKED, not attempted — block PRODUCTION "
            "(onlyValidatorIsUs / a transaction landing in a block / a "
            "restart resuming past a committed tip): DNAC genesis requires "
            "EXACTLY %d equal-stake validators (nodus_witness_v2_gen.c:"
            "582-584, :600-603), so ONE live process can never reach the "
            "+2/3 quorum needed to commit a block on this chain. See this "
            "file's header for the full citation.\n",
            (int)DNAC_COMMITTEE_SIZE);

    for (i = 0; i < ncases; i++) {
        int rc = cases[i].fn();

        fprintf(stderr, "%-30s %s\n", cases[i].name, rc == 0 ? "ok" : "FAIL");
        if (rc != 0) {
            failed++;
        }
    }
    fprintf(stderr, "test_cmt_live: %zu/%zu cases passed, %d checks\n",
            ncases - failed, ncases, g_checks);
    return failed ? 1 : 0;
}
