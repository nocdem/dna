/**
 * Nodus — O15C-D.4 — consensus protocol version gate.
 *
 * ── R3 W4-D REWRITE — WHY THE ORIGINAL FILE IS GONE ───────────────────
 *
 * O15C-D.4 closed a defect where nodus_witness_dispatch_t3 accepted a
 * PREVOTE / NEW_VIEW at an out-of-date protocol version and silently
 * counted its vote under the wrong semantics — reproduced on real
 * binaries (bc0ff148 vs c65c8cd1), where a legacy node's vote was
 * essential to a quorum the current-version nodes could not reach
 * without it.
 *
 * R3 W4-D deletes the closed consensus lane entirely: PROPOSE, PREVOTE,
 * PRECOMMIT, COMMIT, VIEWCHG, NEWVIEW, FWD_REQ, FWD_RSP (verbs 1-8),
 * SYNC_REQ/RSP (12-13), the bootstrap CHAIN_Q/CHAIN_R/GENESIS_REQ/
 * GENESIS_RSP (16-19), the old-lane V2_BLOCK/V2_HEAD/V2_RANGE_REQ/
 * V2_RANGE_RSP (20-23) and VIEWOK/VIEWOK_REQ (26-27) — 20 method
 * strings in all, plus w_cc_vote_req/w_cc_vote_rsp (verbs 14-15,
 * retired separately by D-16 rev 7 / W4-CC, rebuilt as verbs 40-41) —
 * 22 in total — no longer decode to anything: nodus_t3_method_to_
 * type answers 0 for every one of them, and nodus_t3_decode refuses the
 * envelope before any argument is looked at (nodus_tier3.c: "msg->type
 * = nodus_t3_method_to_type(msg->method); if (msg->type == 0) return
 * -1;"). Their arg structs, their dispatch cases and the round_state /
 * bft_config machinery the old test drove through nodus_witness_
 * dispatch_t3 are all deleted with them (nodus_witness_bft.c and
 * nodus_witness_bft_internal.h, whole files).
 *
 * The property this file exists to prove is therefore no longer "the
 * dispatcher gates a live verb by version" — there is no live verb left
 * in the retired set to gate. It is the STRONGER, simpler guarantee
 * that subsumes it: a retired method string does not even decode,
 * regardless of what protocol version its header claims, so there is no
 * way to reach a dispatch-level version check for it at all. §6/§7's
 * "a current-version header carrying legacy-shaped NEW_VIEW args" case
 * is subsumed by the same fact: the method itself is refused before any
 * argument, legacy-shaped or not, is ever read.
 *
 * ── WHAT THIS FILE PROVES ──────────────────────────────────────────────
 *
 *   1. Every one of the 20 retired method strings, hand-built into an
 *      otherwise well-formed envelope carrying this node's OWN current
 *      protocol version, is REFUSED by nodus_t3_decode (return -1), and
 *      nodus_t3_method_to_type answers 0 (not-a-verb) for the same
 *      string directly.
 *   2. CONTROL: the identical envelope SHAPE, naming a LIVE method
 *      (w_rost_q, verb 9) with valid args, DECODES successfully. Without
 *      this control, a decoder that refused every envelope regardless of
 *      content would pass every case above for the wrong reason.
 *
 * ── WHAT THIS FILE DOES NOT PROVE ──────────────────────────────────────
 *
 * The NEW gate — whether a genuine w_cmt_state frame (verb 35) is
 * accepted at this node's protocol version and refused at a version one
 * off in either direction — is `test_cmt_live.c`'s claim, not this
 * file's: its case 2 (`version_gate_verb35`) drives a real signed
 * w_cmt_state frame through nodus_witness_dispatch_t3 at the current
 * version (accepted, the peer's round state moves) and at versions one
 * below and one above (both refused), the two refusals distinguished by
 * distinct heights so neither case is vacuous.
 *
 * ── WHAT IT REQUIRES / LEAVES BEHIND ───────────────────────────────────
 *
 * Nothing beyond a default build: no compile flags, no environment, no
 * network, no filesystem, no witness handle, no signing key. Every case
 * drives nodus_t3_decode / nodus_t3_method_to_type directly on an
 * in-memory buffer; nothing is left behind.
 *
 * ── HOW IT COULD LIE ───────────────────────────────────────────────────
 *
 * Every hand-built envelope is otherwise well-formed (the same 6-key
 * top-level shape and 7-key header the live encoder emits), so a
 * rejection can only be attributed to the METHOD NAME, not to some
 * other malformation the builder introduced by mistake — the control
 * case (w_rost_q) closes this: if the builder itself produced a
 * malformed frame, the control would fail closed too, and it does not.
 */

#include "protocol/nodus_tier3.h"
#include "protocol/nodus_cbor.h"
#include "nodus/nodus_types.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK fail at %s:%d: %s\n", \
                __FILE__, __LINE__, #cond); \
        exit(1); \
    } } while (0)

static int checks;

/* The 20 method strings retired with the closed consensus lane (R3 W4),
 * exactly as nodus_t3_type_to_method answered them before their enum
 * members were deleted (verified against git history at 4a43e3a9), PLUS
 * w_cc_vote_req/w_cc_vote_rsp (verbs 14-15), retired by D-16 rev 7
 * (W4-CC) and rebuilt on the pre-auth envelope as verbs 40-41
 * (w_cc_appr_req/w_cc_appr_rsp — LIVE, not in this list). The numbers
 * behind every retired string here are never reused (nodus_tier3.h's own
 * "RETIRED numbers" comment). */
static const char *const RETIRED_METHODS[] = {
    "w_propose", "w_prevote", "w_precommit", "w_commit",
    "w_viewchg", "w_newview", "w_fwd_req", "w_fwd_rsp",
    "w_sync_req", "w_sync_rsp",
    "w_chain_q", "w_chain_r", "w_genesis_req", "w_genesis_rsp",
    "w_v2_block", "w_v2_head", "w_v2_range_q", "w_v2_range_r",
    "w_viewok", "w_viewok_q",
    "w_cc_vote_req", "w_cc_vote_rsp",
};
#define N_RETIRED (sizeof(RETIRED_METHODS) / sizeof(RETIRED_METHODS[0]))

/* A filler value reused for every bstr field this file's hand-built
 * frames need (sender_id, chain_id) — none of these cases calls
 * nodus_t3_verify, so no real signing key or wsig content is needed;
 * only nodus_t3_decode's method-name gate is under test. */
static uint8_t FILLER[32];

/* The generic hand-built envelope every case below shares — the SAME
 * 6-key top-level shape and 7-key header nodus_t3_encode emits (matching
 * test_tier3.c's w3_frame_begin idiom), so the ONLY thing that varies
 * between a retired-method case and the control is the `q` string and
 * the `a` map's content. */
static void frame_begin(cbor_encoder_t *enc, uint8_t *buf, size_t cap,
                        const char *method) {
    cbor_encoder_init(enc, buf, cap);
    cbor_encode_map(enc, 6);
    cbor_encode_cstr(enc, "t"); cbor_encode_uint(enc, 1);
    cbor_encode_cstr(enc, "y"); cbor_encode_cstr(enc, "q");
    cbor_encode_cstr(enc, "q"); cbor_encode_cstr(enc, method);
    cbor_encode_cstr(enc, "wh");
    cbor_encode_map(enc, 7);
    cbor_encode_cstr(enc, "v");   cbor_encode_uint(enc, NODUS_T3_BFT_PROTOCOL_VER);
    cbor_encode_cstr(enc, "rnd"); cbor_encode_uint(enc, 0);
    cbor_encode_cstr(enc, "vw");  cbor_encode_uint(enc, 0);
    cbor_encode_cstr(enc, "sid"); cbor_encode_bstr(enc, FILLER, sizeof(FILLER));
    cbor_encode_cstr(enc, "ts");  cbor_encode_uint(enc, 1);
    cbor_encode_cstr(enc, "nc");  cbor_encode_uint(enc, 2);
    cbor_encode_cstr(enc, "cid"); cbor_encode_bstr(enc, FILLER, sizeof(FILLER));
    cbor_encode_cstr(enc, "a");
}

static size_t frame_end(cbor_encoder_t *enc) {
    cbor_encode_cstr(enc, "wsig");
    cbor_encode_bstr(enc, FILLER, sizeof(FILLER));
    return cbor_encoder_len(enc);
}

int main(void) {
    printf("=== Consensus protocol version gate (R3 W4-D rewrite) ===\n");

    /* ── §1 every retired method string refuses to decode ────────────
     * §1a: nodus_t3_method_to_type answers 0 (not-a-verb) directly.
     * §1b: a hand-built envelope naming it, at THIS NODE'S OWN current
     * protocol version, is refused by nodus_t3_decode — the method gate
     * fires before the version could ever matter. */
    for (size_t i = 0; i < N_RETIRED; i++) {
        const char *m = RETIRED_METHODS[i];

        CHECK(nodus_t3_method_to_type(m) == 0);

        uint8_t buf[512];
        cbor_encoder_t enc;
        frame_begin(&enc, buf, sizeof(buf), m);
        cbor_encode_map(&enc, 0);   /* empty args — never reached */
        size_t len = frame_end(&enc);
        CHECK(len > 0);

        nodus_t3_msg_t out;
        int rc = nodus_t3_decode(buf, len, &out);
        CHECK(rc != 0);
        checks++;

        printf("[ok] §1 \"%s\" (retired) refused at v%u — "
               "method_to_type == 0, decode == %d\n",
               m, (unsigned)NODUS_T3_BFT_PROTOCOL_VER, rc);
    }

    /* ── §2 CONTROL — the identical shape, a LIVE method, DECODES ─────
     * w_rost_q (verb 9) with valid args {v: uint}. Without this control,
     * every refusal above could mean "this builder never produces a
     * frame nodus_t3_decode accepts", proving nothing about the method
     * name specifically. */
    {
        uint8_t buf[512];
        cbor_encoder_t enc;
        frame_begin(&enc, buf, sizeof(buf), "w_rost_q");
        cbor_encode_map(&enc, 1);
        cbor_encode_cstr(&enc, "v"); cbor_encode_uint(&enc, 7);
        size_t len = frame_end(&enc);
        CHECK(len > 0);

        nodus_t3_msg_t out;
        CHECK(nodus_t3_decode(buf, len, &out) == 0);
        CHECK(out.type == NODUS_T3_ROST_Q);
        CHECK(out.header.version == NODUS_T3_BFT_PROTOCOL_VER);
        CHECK(out.rost_q.version == 7);
        checks++;

        printf("[ok] §2 CONTROL \"w_rost_q\" (live) decodes at v%u — "
               "the builder itself is not what refused §1\n",
               (unsigned)NODUS_T3_BFT_PROTOCOL_VER);
    }

    /* The version gate on the LIVE cometbft envelope verbs (35-39) —
     * whether a genuine w_cmt_state frame is accepted at this node's own
     * protocol version and refused one version off in either direction —
     * is test_cmt_live.c's claim (its version_gate_verb35 case), not
     * this file's: proving it needs a real dispatch through a live
     * nodus_witness_t and cmt_conr_t/cmt_memr_t pair, which this file
     * deliberately does not build. */

    printf("\n%d checks passed\n", checks);
    printf("PASS test_witness_protocol_version_gate\n");
    return 0;
}
