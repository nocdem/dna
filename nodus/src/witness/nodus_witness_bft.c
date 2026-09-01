/**
 * Nodus — Witness BFT Consensus Engine
 *
 * BFT consensus for DNAC transaction witnessing.
 * Ported from dnac/src/bft/consensus.c (2168 lines).
 *
 * Key adaptations from DNAC:
 *   - No pthreads (single-threaded in epoll loop)
 *   - CBOR via nodus_t3_encode/decode (not binary serialization)
 *   - Direct nodus_witness_db calls (not callback indirection)
 *   - Signing handled by T3 encode layer
 *
 * Consensus flow: PROPOSE → PREVOTE → PRECOMMIT → COMMIT
 *   - Genesis requires unanimous (N/N) approval
 *   - Normal transactions require quorum (2f+1)
 *   - Round timeout triggers view change
 */

#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_merkle.h"
#include "witness/nodus_witness_verify.h"
#include "witness/nodus_witness_handlers.h"
#include "witness/nodus_witness_cert.h"
#include "witness/nodus_witness_v2_result.h"  /* typed cert-verify result codes */
#include "witness/nodus_witness_validator.h"
#include "witness/nodus_witness_committee.h"
#include "witness/nodus_witness_delegation.h"
#include "witness/nodus_witness_epoch.h"
#include "witness/nodus_witness_emission.h"
#include "witness/nodus_witness_genesis_seed.h"
#include "witness/nodus_witness_vset.h"        /* S3 epoch validator-set lifecycle */
#include "witness/nodus_witness_sync.h"        /* A2 simetri: active sync_check trigger */
#include "witness/nodus_witness_v2_sync2.h"    /* O15G: successor catch-up tick   */
#include "witness/nodus_witness_v2_produce.h"    /* O15D successor rounds */
#include "witness/nodus_witness_v2_env.h"        /* metered batch check +
                                                  * the refusal KIND     */
#include "witness/nodus_witness_v2_claims.h"    /* O15K V-3 — the spent-claim
                                                  * table a class-201 commit
                                                  * writes and the legacy
                                                  * nullifier walk cannot see */
#include "witness/nodus_witness_runtime.h"      /* O15N Faz 2B —
                                                  * nodus_rt_committee_set_hash,
                                                  * the ONE "DNA.CCSET.v1"
                                                  * derivation every signer,
                                                  * the engine and the auth
                                                  * hook already share.
                                                  * ALREADY reachable through
                                                  * nodus_witness_v2_claims.h
                                                  * above; named here so this
                                                  * file's dependency does not
                                                  * rest on another header's
                                                  * include list. */
#include "nodus/nodus_chain_config.h"          /* Hard-Fork v1 apply dispatch */
#include "protocol/nodus_tier3.h"
#include "server/nodus_server.h"
#include "transport/nodus_tcp.h"
#include "crypto/nodus_sign.h"
#include "crypto/utils/qgp_bench.h"   /* perf harness — ((void)0) in production */

#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_u128.h"
#include "crypto/utils/qgp_fingerprint.h"

#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"     /* O15H C5 — dna_bft_quorum(n) */
#include "witness/nodus_witness_o15h_diag.h"  /* O15H TEMPORARY tracing */
#include "dnac/safe_math.h"      /* safe_add_u64 for SEC-01 consistency check */
#include "dnac/validator.h"
#include "dnac/transaction.h"   /* DNAC_STAKE_PURPOSE_TAG_LEN */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>   /* O15N Faz 2C2 — offsetof, for the VIEW_OK store's
                       * layout pin against the wire cert entry */
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "crypto/utils/qgp_log.h"

#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

#define LOG_TAG "WITNESS-BFT"

/* Client spend-result status codes. Mirror of the file-local defines in
 * nodus_witness_handlers.c:54-56, which is the authority — they are not
 * published in any header, and nodus_witness_send_spend_result() takes
 * the status as a plain int. */
#define DNAC_STATUS_APPROVED   0
#define DNAC_STATUS_ERROR      2

/* Forward declaration — defined near bft_check_timeout */
static void round_state_free_batch(nodus_witness_round_state_t *rs);
static void bft_emit_batch_replies(nodus_witness_t *w, int status,
                                    const char *error_msg);

/* Phase 6 commit wrappers — defined later in this file. Forward
 * declarations let the Phase 7 / Task 7.6 dispatchers (commit_block,
 * the local batch path, the remote batch path) call them without
 * pulling the test-only nodus_witness_bft_internal.h header. */
int nodus_witness_commit_genesis(nodus_witness_t *w,
                                   const uint8_t *tx_hash,
                                   const uint8_t *tx_data,
                                   uint32_t tx_len,
                                   uint64_t timestamp,
                                   const uint8_t *proposer_id);
int nodus_witness_commit_batch(nodus_witness_t *w,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t expected_height,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id,
                                 const uint8_t *expected_state_root);

/* O15N Faz 2C2 — the catch-up ask. Defined beside the VIEW_OK machinery
 * below; declared here because handle_propose, which sits far above it,
 * is one of the two sites that refuse a message for a view mismatch and
 * therefore one of the two that must ask. */
static void bft_viewok_send_request(nodus_witness_t *w,
                                      const uint8_t *peer_id);

/* ── Time helper ─────────────────────────────────────────────────── */

static uint64_t time_ms(void) {
    return nodus_time_now() * 1000ULL;
}

/* ── C5 — PBFT prepared-cert preimage helper ─────────────────────── */

/* Preimage layout (116 bytes, O15N Faz 2A — was 76):
 *
 *   [0..7]     "prepared"   8 bytes ASCII, NO NUL terminator
 *   [8..39]    chain_id     32 bytes
 *   [40..43]   view         uint32 big-endian
 *   [44..51]   height       uint64 big-endian
 *   [52..115]  tx_hash      64 bytes (NODUS_T3_TX_HASH_LEN)
 *
 * Signed via nodus_sign_prepared_vote, which wraps this in the NDS1 tag
 * under purpose 0x07. That wrapping is REAL as of this protocol bump: 0x07
 * is now strict (nodus_sign_purpose_is_strict), so the signer tags and the
 * verifier refuses an untagged signature. Before the bump the claim was
 * FALSE — nodus_sign_tagged discarded the purpose byte and signed raw, and
 * nodus_verify_tagged fell back to a raw verify for every purpose.
 *
 * Why chain_id is in here: this network wipes chains, and (view, height)
 * pairs repeat on the successor. Without a chain identity in the preimage,
 * a signature harvested before a wipe stays valid after it.
 *
 * ⚠ HONEST LABEL — THIS BINDING IS 128 BITS, NOT 256. `w->chain_id` is the
 * LEGACY identity: 16 significant bytes zero-padded to 32
 * (nodus_witness_set_chain_id, nodus_witness.c:286-301). The V2 envelope
 * lane refuses this value for exactly that reason and uses the committed
 * genesis BlockID instead (nodus_witness_v2_env.c:80-87). It is used HERE
 * anyway, deliberately: this preimage is built on BOTH the legacy and the
 * successor lane, the V2 identity does not exist on a legacy chain, and
 * `verify_chain_id` — the message-layer cross-chain gate this preimage
 * backs up — already compares these same 32 bytes
 * (nodus_witness_bft.c, verify_chain_id). Using a different chain identity
 * here than the gate beside it would be the anomaly. Two chains would have
 * to share a 16-byte derived prefix to make a harvested signature
 * transferable; raising this to a full 32-byte identity means giving the
 * witness a stored untruncated chain hash, which is a change of its own.
 *
 * Why the leading "prepared" tag: it separates this statement from any
 * other 108-byte-suffixed structure that might one day be signed under a
 * neighbouring purpose, independently of the NDS1 layer above it. */
#define NODUS_WITNESS_PREPARED_TAG      "prepared"
#define NODUS_WITNESS_PREPARED_TAG_LEN  8
#define NODUS_WITNESS_PREPARED_CHAIN_ID_LEN  32
#define NODUS_WITNESS_PREPARED_PREIMAGE_LEN  116

/* The layout cannot drift from the constant: every field width is summed
 * here, and the chain_id width is taken from the struct field the callers
 * actually pass, not from a repeated literal. */
_Static_assert(NODUS_WITNESS_PREPARED_TAG_LEN + NODUS_WITNESS_PREPARED_CHAIN_ID_LEN +
                   4 + 8 + NODUS_T3_TX_HASH_LEN ==
                   NODUS_WITNESS_PREPARED_PREIMAGE_LEN,
               "PREPARED preimage field widths must sum to 116");
_Static_assert(sizeof(((nodus_witness_t *)0)->chain_id) ==
                   NODUS_WITNESS_PREPARED_CHAIN_ID_LEN,
               "PREPARED preimage assumes nodus_witness_t.chain_id is 32 bytes");
_Static_assert(sizeof(NODUS_WITNESS_PREPARED_TAG) - 1 ==
                   NODUS_WITNESS_PREPARED_TAG_LEN,
               "PREPARED domain tag must be exactly 8 ASCII bytes");

static int compute_prepared_preimage(uint32_t view,
                                       uint64_t height,
                                       const uint8_t *tx_hash,
                                       const uint8_t *chain_id,
                                       uint8_t out[NODUS_WITNESS_PREPARED_PREIMAGE_LEN]) {
    if (!tx_hash || !chain_id || !out) return -1;

    /* [0..7] domain tag, 8 ASCII bytes, no NUL */
    memcpy(out, NODUS_WITNESS_PREPARED_TAG, NODUS_WITNESS_PREPARED_TAG_LEN);

    /* [8..39] chain_id (32 bytes) */
    memcpy(out + 8, chain_id, NODUS_WITNESS_PREPARED_CHAIN_ID_LEN);

    /* [40..43] view (big-endian uint32) */
    out[40] = (uint8_t)((view >> 24) & 0xFF);
    out[41] = (uint8_t)((view >> 16) & 0xFF);
    out[42] = (uint8_t)((view >>  8) & 0xFF);
    out[43] = (uint8_t)(view & 0xFF);

    /* [44..51] height (big-endian uint64) */
    for (int i = 0; i < 8; i++)
        out[44 + i] = (uint8_t)((height >> ((7 - i) * 8)) & 0xFF);

    /* [52..115] tx_hash (64 bytes) */
    memcpy(out + 52, tx_hash, NODUS_T3_TX_HASH_LEN);

    return 0;
}

/* ── O15N Faz 2B — the VIEW_OK preimage ──────────────────────────── */

/* Preimage layout (148 bytes):
 *
 *   [0..7]      "viewok\0\0"        8 bytes: 6 ASCII + 2 NUL pad
 *   [8..39]     chain_id            32 bytes
 *   [40..47]    height              uint64 big-endian
 *   [48..51]    view                uint32 big-endian
 *   [52..115]   committee_set_hash  64 bytes ("DNA.CCSET.v1")
 *   [116..147]  voter_id            32 bytes
 *
 * Signed via nodus_sign_view_ok under purpose 0x08, which is STRICT
 * (nodus_sign_purpose_is_strict) — the NDS1 tag is mandatory on the
 * signing AND the verifying side, so a signature made over the
 * undecorated bytes is refused.
 *
 * WHAT THIS STATEMENT MEANS. Not "I vote for view V" — "I OBSERVED a
 * view-change quorum for V at height H, under the committee whose set
 * hash is this". An honest node emits it at exactly one instant: when its
 * own per-voter tally first reaches quorum (bft_vc_check_quorum). A vote
 * would NOT be safe to accumulate — voters re-emit at every rung of the
 * escalation ladder and nothing retracts — but an outcome statement is
 * produced at most once per (height, view) and describes something that
 * really happened.
 *
 * Field-by-field, why each is in the signed bytes:
 *
 *  - chain_id: this network wipes chains and (height, view) pairs repeat
 *    on the successor. Without it a statement harvested before a wipe
 *    stays valid after it. Same 32 bytes and the SAME honest label as the
 *    PREPARED preimage above: w->chain_id is the LEGACY identity, 16
 *    significant bytes zero-padded to 32 (nodus_witness_set_chain_id,
 *    nodus_witness.c) — a 128-bit binding, not 256. It is used here for
 *    the same reason it is used there: verify_chain_id, the message-layer
 *    gate this backs up, compares these exact bytes, and using a
 *    different chain identity beside it would be the anomaly.
 *  - height: a view change is about a specific undecided sequence
 *    number; without it a statement from one height proves a view at
 *    every other.
 *  - view: the counter the statement is evidence for.
 *  - committee_set_hash: the AUTHORITY the signer measured its own
 *    quorum against, committing both membership and seat positions
 *    (nodus_rt_committee_set_hash). A reader that resolves a different
 *    set knows it cannot judge, instead of judging with the wrong
 *    denominator.
 *  - voter_id: makes each statement individual. Without it every signer
 *    signs identical bytes and one signature is trivially re-labelled
 *    under another voter's id, so f+1 "distinct" signatures could be one
 *    signature repeated.
 *
 * Why the leading tag is 8 bytes: it matches the other in-preimage tags
 * in this tree (NODUS_WITNESS_CERT_DOMAIN_TAG, nodus_witness_cert.c) and
 * the "prepared" tag above. "viewok" is 6 chars, so the two pad bytes are
 * written EXPLICITLY below — never as a string literal's terminator,
 * which would leave the second pad byte undefined. */
#define NODUS_WITNESS_VIEWOK_TAG_LEN        8
#define NODUS_WITNESS_VIEWOK_TAG_ASCII_LEN  6   /* "viewok", then 2 NUL pad */
#define NODUS_WITNESS_VIEWOK_CHAIN_ID_LEN   32
#define NODUS_WITNESS_VIEWOK_SET_HASH_LEN   64
#define NODUS_WITNESS_VIEWOK_PREIMAGE_LEN   148

/* The layout cannot drift from the constant: every field width is summed
 * here, the tag is pinned at 8 bytes independently of its ASCII length
 * (they DIFFER — 6 chars plus 2 pad), and the chain_id width is taken
 * from the struct field the callers actually pass. */
_Static_assert(NODUS_WITNESS_VIEWOK_TAG_LEN +
                   NODUS_WITNESS_VIEWOK_CHAIN_ID_LEN + 8 + 4 +
                   NODUS_WITNESS_VIEWOK_SET_HASH_LEN +
                   NODUS_T3_WITNESS_ID_LEN ==
                   NODUS_WITNESS_VIEWOK_PREIMAGE_LEN,
               "VIEW_OK preimage field widths must sum to 148");
_Static_assert(sizeof(((nodus_witness_t *)0)->chain_id) ==
                   NODUS_WITNESS_VIEWOK_CHAIN_ID_LEN,
               "VIEW_OK preimage assumes nodus_witness_t.chain_id is 32 bytes");
_Static_assert(sizeof("viewok") - 1 == NODUS_WITNESS_VIEWOK_TAG_ASCII_LEN,
               "the VIEW_OK domain tag must be exactly 6 ASCII bytes, "
               "zero-padded to 8 — the pad is written explicitly");
_Static_assert(NODUS_WITNESS_VIEWOK_TAG_ASCII_LEN + 2 ==
                   NODUS_WITNESS_VIEWOK_TAG_LEN,
               "the VIEW_OK tag is 6 ASCII bytes plus EXACTLY 2 pad bytes; "
               "both pad bytes are written explicitly, never inherited from "
               "a string literal's terminator");

static int compute_view_ok_preimage(uint64_t height,
                                      uint32_t view,
                                      const uint8_t *set_hash,
                                      const uint8_t *voter_id,
                                      const uint8_t *chain_id,
                                      uint8_t out[NODUS_WITNESS_VIEWOK_PREIMAGE_LEN]) {
    if (!set_hash || !voter_id || !chain_id || !out) return -1;

    /* [0..7] domain tag: 6 ASCII bytes then TWO explicit NUL pad bytes. */
    memcpy(out, "viewok", NODUS_WITNESS_VIEWOK_TAG_ASCII_LEN);
    out[6] = 0x00;
    out[7] = 0x00;

    /* [8..39] chain_id (32 bytes) */
    memcpy(out + 8, chain_id, NODUS_WITNESS_VIEWOK_CHAIN_ID_LEN);

    /* [40..47] height (big-endian uint64) */
    for (int i = 0; i < 8; i++)
        out[40 + i] = (uint8_t)((height >> ((7 - i) * 8)) & 0xFF);

    /* [48..51] view (big-endian uint32) */
    out[48] = (uint8_t)((view >> 24) & 0xFF);
    out[49] = (uint8_t)((view >> 16) & 0xFF);
    out[50] = (uint8_t)((view >>  8) & 0xFF);
    out[51] = (uint8_t)(view & 0xFF);

    /* [52..115] committee_set_hash (64 bytes) */
    memcpy(out + 52, set_hash, NODUS_WITNESS_VIEWOK_SET_HASH_LEN);

    /* [116..147] voter_id (32 bytes) */
    memcpy(out + 116, voter_id, NODUS_T3_WITNESS_ID_LEN);

    return 0;
}

/* ── O15N Faz 2B — the committee set hash on the BFT path ────────── */

/* The 64-byte "DNA.CCSET.v1" hash over a resolved committee.
 *
 * The derivation itself is NOT reimplemented here: it is
 * nodus_rt_committee_set_hash (nodus_witness_rt_native.c), the ONE
 * expression the apply engine, the auth hook and every signer share.
 * This helper only does what that function's fps[] contract requires —
 * SHA3-512 each member's pubkey into a fingerprint.
 *
 * ⚠ THE ORDER IS NOT SORTED, DELIBERATELY. The fps go in the order the
 * committee resolver returned them (the stake-ranked seat order), because
 * the hash commits both MEMBERSHIP AND SEAT POSITIONS — and the seat
 * order is what leader election reads. Sorting here would make two
 * committees with the same members but different seats hash identically,
 * which is exactly the distinction a view-authority statement must keep.
 *
 * ⚠ HEAP, NOT STACK. At DNAC_MAX_ACTIVE_VALIDATORS = 128 the fps array is
 * 8192 bytes; the witness path does not carry multi-kilobyte automatics
 * (same rule that made load_committee_at_height_alloc heap-allocating).
 *
 * A hash-backend failure or an empty committee is a FAULT, not a value:
 * this returns -1 and the caller fails closed. It never emits a zero or
 * an "empty set" hash — such a value would be a statement about a
 * committee that does not exist, and two nodes could agree on it while
 * agreeing on nothing real.
 *
 * @return 0 on success (out64 filled), -1 on any fault. */
static int compute_committee_set_hash(const nodus_committee_member_t *members,
                                        int count,
                                        uint8_t out64[64]) {
    if (!members || !out64) return -1;
    if (count <= 0 || count > DNAC_MAX_ACTIVE_VALIDATORS) return -1;

    uint8_t (*fps)[64] = calloc((size_t)count, 64);
    if (!fps) return -1;

    for (int i = 0; i < count; i++) {
        if (qgp_sha3_512(members[i].pubkey, DNAC_PUBKEY_SIZE, fps[i]) != 0) {
            free(fps);
            return -1;
        }
    }

    int rc = nodus_rt_committee_set_hash((const uint8_t (*)[64])fps,
                                           (uint32_t)count, out64);
    free(fps);
    return (rc == 0) ? 0 : -1;
}

/* ── Replay prevention ───────────────────────────────────────────── */

/* ── Nonce hash table (HIGH-2: replaces linear-scan array) ──────── */

/* ════════════════════════════════════════════════════════════════════
 * O15O Faz 5 — WHO PAYS FOR AN ENTRY, AND WHO DECIDES WHAT LEAVES
 *
 * Two defects were closed here, and they are one mechanism seen from two
 * sides. Both are in nodus/BUGS.md; both are about the SIZE and the
 * EVICTION ORDER of this cache, not about its hashing.
 *
 * ── A. THE ATTACKER ONE (BUGS.md O15N-L1) ────────────────────────────
 * The table held NONCE_MAX_TOTAL = 10000 entries GLOBALLY and, at
 * capacity, freed an ENTIRE BUCKET chosen by the smallest `timestamp` —
 * a field written straight from the caller's `timestamp` argument, which
 * every one of the six call sites takes from `hdr->timestamp`. THE
 * SENDER CHOOSES AND SIGNS THAT NUMBER, so a sender decided WHICH honest
 * entries left the table, and the eviction order of a consensus-path
 * cache was an attacker input. One crafted frame stamped at the old end
 * of the freshness window (now - 299) ranks as the global minimum and
 * takes its whole bucket — roughly 39 entries at capacity, almost all of
 * them honest — with the bucket selectable by grinding the nonce.
 *
 * ⚠ ONE HALF OF THE BUGS.md WRITE-UP DOES NOT SURVIVE THE CODE, and it
 * is recorded here so nobody re-derives it. That entry names FAR-FUTURE
 * stamps as the mechanism ("its own entries then rank NEWEST"). They do
 * not: the TTL comparison is `now - n->timestamp >= NONCE_TTL_SECS` on
 * uint64 values, so a FUTURE timestamp underflows to ~2^64 and the entry
 * is treated as ALREADY EXPIRED. Future-stamped entries are purged by
 * the next sweep of their bucket and can never accumulate, so a
 * far-future flood fills nothing. The entry's CONCLUSION is right and
 * its stated route is not; the PAST-stamped route above is the one that
 * works. The underflow itself is left as-is (it only ever shortens the
 * life of the stamping sender's OWN entry, which is the same accepted
 * residual class as record-after-the-gates) and is out of this phase.
 *
 * ── B. THE HONEST ONE (BUGS.md, "the replay cache can be exhausted by
 *      HONEST traffic") ──────────────────────────────────────────────
 * Derived from shipped constants, no attacker involved:
 *
 *     TTL                                   300 s (NONCE_TTL_SECS)
 *     fastest permitted round                 1 s
 *                       (DNAC_CFG_MIN_BLOCK_INTERVAL_SEC, dnac.h:341 —
 *                        governance MAY set it that low, so the bound
 *                        must hold there)
 *     broadcasts per node per round           ~4
 *                       (PREVOTE + PRECOMMIT + COMMIT, plus PROPOSE on
 *                        the 1-in-n rounds it leads)
 *     ⇒ per honest sender per TTL window   ~1200 nonces
 *
 * Against a global 10000 that is ~8400 at 7 seats (fits, barely),
 * ~10800 at 9 (over) and ~24000 at 20 (far over). The cache evicted
 * under NORMAL operation, and every eviction re-opens the window the
 * cache exists to close — the O15H D9 safety argument leans on it in as
 * many words (see the note at the VIEW_CHANGE upsert below).
 *
 * B IS WHY THE SIZING IS PER-SENDER-FIRST. Dividing a fixed 10000 by n
 * only moves the squeeze from "the whole table" to "each sender's
 * slice"; the primitive has to be the share, and the total has to be
 * derived from it.
 *
 * ── THE THREE CHANGES ────────────────────────────────────────────────
 *
 * 1. CHECK AND RECORD ARE SEPARATE CALLS. `is_replay` is now PURE: it
 *    reads, it never inserts and never evicts. `nonce_record` is called
 *    by each handler AFTER its chain_id AND committee gates have passed
 *    and BEFORE its first state mutation. An unauthorised sender
 *    therefore consumes none of the capacity that protects authorised
 *    ones.
 *
 *    ⚠ THE HONEST CONSEQUENCE, stated so the next reader does not have
 *    to derive it: a frame that passes authorization but is dropped by a
 *    LATER gate is NOT recorded, so it can be re-presented. That is
 *    accepted. Replaying an AUTHORISED COMMITTEE MEMBER's own frame is
 *    what the round, view and height guards exist to handle — a stale
 *    round dies at the round check, a stale view at the view check, a
 *    stale height at the height check, and a buffered vote is deduped on
 *    (sender, type, round, view) with keep-first by
 *    bft_vote_buffer_insert. It also REMOVES a shipped hazard the O15M
 *    note in handle_newview names as a candidate cause of its measured
 *    stall: "is_replay INSERTING the nonce on a call whose handler later
 *    refuses the message for a transient reason (committee not
 *    loadable, cert unverifiable), so that the delivery which WOULD have
 *    succeeded is then refused as a duplicate." That can no longer
 *    happen for a transient refusal at or below a committee gate.
 *    NOTHING is added to handle_newview here; that site keeps its
 *    documented refusal to carry a replay check at all.
 *
 * 2. THE BUDGET IS PER SENDER AND THE TOTAL IS DERIVED. See
 *    NONCE_MAX_PER_SENDER below. When a sender is at ITS cap the entry
 *    that leaves is THAT SENDER'S OWN OLDEST — a flooder can only ever
 *    evict itself.
 *
 * 3. "OLDEST" IS A NODE-LOCAL COUNTER, NEVER THE WIRE TIMESTAMP. Each
 *    entry carries `seq`, assigned from a monotonically increasing
 *    node-local counter at insert.
 *
 *    DETERMINISM NOTE: this REMOVES a sender-controlled input from a
 *    consensus-path decision. It does NOT add a clock — a counter is not
 *    a time source, it reads nothing outside this table, and two nodes
 *    are not required to agree on it (the cache is a per-node message-
 *    admission structure, not consensus state).
 *
 * ── WHAT WAS CONSIDERED AND LEFT ─────────────────────────────────────
 *  - `is_replay`'s ±300 s freshness window still calls time(NULL). It is
 *    a per-node message-admission gate, it predates this season, and it
 *    is not this phase's subject. LEFT DELIBERATELY.
 *  - TTL expiry still measures against the WIRE timestamp, so an entry
 *    lives between 0 s and 600 s of wall clock rather than exactly 300.
 *    The freshness window bounds it; the residual is that a sender can
 *    make its OWN entry expire early and replay its OWN frame, which is
 *    the same accepted residual class as the record-after-the-gates
 *    consequence above. Changing the basis to node-local receipt time
 *    would alter expiry for honest traffic and is not in this phase.
 *  - malloc failure in nonce_record leaves the frame ADMITTED but
 *    UNRECORDED. That is the pre-existing behaviour of the shipped code
 *    (the old insert was `if (node)` with no else) and is unchanged.
 *
 * SINGLE-THREADED EPOLL: no locking anywhere in this section, and none
 * is needed — every caller runs on the one event-loop thread.
 * ════════════════════════════════════════════════════════════════════ */

#define NONCE_BUCKET_COUNT  256
#define NONCE_TTL_SECS      300  /* 5 minutes */

/* THE PRIMITIVE. 2048 is the ~1200-nonce honest need computed above
 * (TTL 300 s × 1/interval 1 s × ~4 frames per round) rounded up to the
 * next power of two for headroom: view-change storms, a leader's extra
 * PROPOSE, and a node that broadcasts twice on a re-entry all fit under
 * it without a single eviction. */
#define NONCE_MAX_PER_SENDER  2048

/* THE DERIVED TOTAL, and it is STRUCTURAL rather than counted.
 *
 * There is deliberately NO global counter and NO global eviction path
 * any more: a cross-sender eviction is precisely the mechanism defect A
 * exploited, so keeping one "as a backstop" would keep the defect. The
 * bound holds by construction instead:
 *
 *   is_replay never inserts + nonce_record runs only after a committee
 *   gate ⇒ only committee members (or, pre-genesis, gossip-roster
 *   members) can ever own an entry ⇒ at most NONCE_MAX_SENDERS distinct
 *   senders hold entries ⇒ at most NONCE_MAX_SENDERS ×
 *   NONCE_MAX_PER_SENDER entries exist.
 *
 * MEMORY. sizeof(nonce_node_t) is 64 B (32 sender_id + 8 nonce +
 * 8 timestamp + 8 seq + 8 next). BUGS.md's 56 B is the PRE-`seq` struct;
 * this phase adds the ordering field, so the honest figures are:
 *
 *   n = 7   saturated   7 × 2048 × 64 B  ≈  918 kB
 *   n = 128 ceiling   128 × 2048 × 64 B  =  16 MiB
 *
 * and only if every seat saturates its whole share, which needs the
 * 1-second block interval AND every seat broadcasting at the cap. At the
 * shipped devnet shape the live table is ~7 × 1200 × 64 B ≈ 538 kB. The
 * slot array itself is fixed and tiny (128 × 48 B ≈ 6 kB in .bss). */
#define NONCE_MAX_SENDERS     NODUS_T3_MAX_WITNESSES

typedef struct nonce_node {
    uint8_t  sender_id[NODUS_T3_WITNESS_ID_LEN];
    uint64_t nonce;
    uint64_t timestamp;   /* WIRE stamp — TTL expiry ONLY, never ordering */
    uint64_t seq;         /* node-local insert order — THE ordering key    */
    struct nonce_node *next;
} nonce_node_t;

/* Per-sender accounting. `count` is the number of live nodes carrying
 * this sender_id; it is maintained by ONE free funnel and ONE insert, so
 * the two structures cannot drift. A slot with count == 0 is recyclable
 * even while `used` is still set — releasing it inside the funnel would
 * mean a caller holding the slot across an eviction could resurrect a
 * released slot, so release is lazy and lives in nonce_sender_claim. */
typedef struct {
    bool     used;
    uint8_t  sender_id[NODUS_T3_WITNESS_ID_LEN];
    uint32_t count;
    uint64_t last_seq;   /* newest seq this sender ever inserted — the
                          * least-recently-active rule when slots run out */
} nonce_sender_t;

static nonce_node_t   *nonce_buckets[NONCE_BUCKET_COUNT];
static nonce_sender_t  nonce_senders[NONCE_MAX_SENDERS];

/* The node-local ordering counter. Starts at 1 so 0 can never be a real
 * seq, and a slot's last_seq of 0 therefore means "has inserted nothing
 * yet" — which makes such a slot the first LRU victim, correctly. At one
 * insert per microsecond a uint64_t wraps in ~584000 years; no wrap
 * handling is written because none is reachable. */
static uint64_t nonce_seq_next = 1;

static uint32_t nonce_hash_fn(const uint8_t *sender_id, uint64_t nonce) {
    uint32_t h = 0x811c9dc5;
    for (int i = 0; i < NODUS_T3_WITNESS_ID_LEN; i++) {
        h ^= sender_id[i];
        h *= 0x01000193;
    }
    for (int i = 0; i < 8; i++) {
        h ^= (uint8_t)(nonce >> (i * 8));
        h *= 0x01000193;
    }
    return h % NONCE_BUCKET_COUNT;
}

/** The slot holding `sender_id`, or NULL. Linear over at most
 *  NONCE_MAX_SENDERS = 128 slots; a 32-byte memcmp each, and only over
 *  slots that are in use. */
static nonce_sender_t *nonce_sender_find(const uint8_t *sender_id) {
    for (int i = 0; i < NONCE_MAX_SENDERS; i++) {
        nonce_sender_t *s = &nonce_senders[i];
        if (s->used && memcmp(s->sender_id, sender_id,
                              NODUS_T3_WITNESS_ID_LEN) == 0)
            return s;
    }
    return NULL;
}

/** THE ONE FREE PATH. Unlinks `*pp` from its bucket chain, decrements
 *  the owning sender's count and frees the node. Every removal in this
 *  file goes through here, which is what keeps `count` and the chains
 *  from drifting.
 *
 *  `hint` is the owning slot when the caller already has it (every
 *  per-sender path does), NULL when it does not (the bucket TTL sweep,
 *  which walks entries of mixed senders). */
static void nonce_unlink_free(nonce_node_t **pp, nonce_sender_t *hint) {
    nonce_node_t *n = *pp;
    *pp = n->next;
    nonce_sender_t *s = hint ? hint : nonce_sender_find(n->sender_id);
    if (s && s->count > 0) s->count--;
    free(n);
}

/** TTL sweep of ONE bucket. Mixed senders, so no hint. */
static void nonce_evict_bucket(uint32_t bucket, uint64_t now) {
    nonce_node_t **pp = &nonce_buckets[bucket];
    while (*pp) {
        if (now - (*pp)->timestamp >= NONCE_TTL_SECS)
            nonce_unlink_free(pp, NULL);
        else
            pp = &(*pp)->next;
    }
}

/** Free every entry belonging to `s` and release its slot.
 *
 *  Reached ONLY when all NONCE_MAX_SENDERS slots are occupied and a new
 *  authorised sender needs one — which requires more than 128 DISTINCT
 *  senders that each passed a committee gate inside one 300 s TTL
 *  window, i.e. a committee turnover at an epoch boundary. Dropping a
 *  slot re-opens self-replay for that one sender until it inserts again;
 *  that is the same accepted residual class as record-after-the-gates,
 *  and it is node-local. */
static void nonce_sender_drop(nonce_sender_t *s) {
    for (uint32_t b = 0; b < NONCE_BUCKET_COUNT; b++) {
        nonce_node_t **pp = &nonce_buckets[b];
        while (*pp) {
            if (memcmp((*pp)->sender_id, s->sender_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0)
                nonce_unlink_free(pp, s);
            else
                pp = &(*pp)->next;
        }
    }
    s->used     = false;
    s->count    = 0;
    s->last_seq = 0;
}

/** The slot for `sender_id`, creating it if needed. Never NULL.
 *
 *  A slot that is `used` with count == 0 is recyclable — that is the
 *  lazy release the funnel deliberately does not perform. If every slot
 *  is both used and non-empty, the LEAST RECENTLY ACTIVE one (smallest
 *  last_seq — a node-local counter, never a wire value) is dropped. */
static nonce_sender_t *nonce_sender_claim(const uint8_t *sender_id) {
    nonce_sender_t *reusable = NULL;

    for (int i = 0; i < NONCE_MAX_SENDERS; i++) {
        nonce_sender_t *s = &nonce_senders[i];
        if (s->used && memcmp(s->sender_id, sender_id,
                              NODUS_T3_WITNESS_ID_LEN) == 0)
            return s;
        if (!reusable && (!s->used || s->count == 0))
            reusable = s;
    }

    if (!reusable) {
        nonce_sender_t *lru = &nonce_senders[0];
        for (int i = 1; i < NONCE_MAX_SENDERS; i++) {
            if (nonce_senders[i].last_seq < lru->last_seq)
                lru = &nonce_senders[i];
        }
        nonce_sender_drop(lru);
        reusable = lru;
    }

    reusable->used     = true;
    reusable->count    = 0;
    reusable->last_seq = 0;
    memcpy(reusable->sender_id, sender_id, NODUS_T3_WITNESS_ID_LEN);
    return reusable;
}

/** Pass 1 of the cap enforcement: free `s`'s EXPIRED entries.
 *
 *  Without it, dead entries inflate `count` and a sender would evict
 *  LIVE nonces while holding hundreds of expired ones — at ~4 frames per
 *  second that is hundreds of phantom slots. The bucket sweep only ever
 *  touches the ONE bucket a frame hashes to, so it cannot do this job. */
static void nonce_sender_sweep(nonce_sender_t *s, uint64_t now) {
    for (uint32_t b = 0; b < NONCE_BUCKET_COUNT; b++) {
        nonce_node_t **pp = &nonce_buckets[b];
        while (*pp) {
            nonce_node_t *n = *pp;
            if (memcmp(n->sender_id, s->sender_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0 &&
                now - n->timestamp >= NONCE_TTL_SECS)
                nonce_unlink_free(pp, s);
            else
                pp = &n->next;
        }
    }
}

/** Pass 2: free `s`'s OLDEST entry, ranked by the node-local `seq`.
 *
 *  A SECOND full pass rather than one fused pass, deliberately: a fused
 *  pass has to carry a `nonce_node_t **` to the best-so-far across
 *  frees, and the argument that the remembered slot cannot dangle is
 *  subtle enough to be got wrong by a later edit. Two passes cost one
 *  extra walk of a table whose size is already bounded by the constants
 *  above, on a path only a sender AT ITS OWN CAP ever reaches. */
static void nonce_sender_evict_oldest(nonce_sender_t *s) {
    uint64_t best_seq = UINT64_MAX;
    uint32_t best_bucket = 0;

    for (uint32_t b = 0; b < NONCE_BUCKET_COUNT; b++) {
        for (nonce_node_t *n = nonce_buckets[b]; n; n = n->next) {
            if (n->seq < best_seq &&
                memcmp(n->sender_id, s->sender_id,
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                best_seq    = n->seq;
                best_bucket = b;
            }
        }
    }
    if (best_seq == UINT64_MAX) return;   /* nothing of ours is live */

    /* `seq` alone would identify the node — the counter never repeats —
     * but the sender is compared too, so the removal does not rest on an
     * invariant a reader has to go and check. */
    nonce_node_t **pp = &nonce_buckets[best_bucket];
    while (*pp) {
        if ((*pp)->seq == best_seq &&
            memcmp((*pp)->sender_id, s->sender_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0) {
            nonce_unlink_free(pp, s);
            return;
        }
        pp = &(*pp)->next;
    }
}

/** THE CHECK — PURE. Reads the table, inserts nothing, evicts nothing.
 *
 *  Called at the top of every handler that has a replay gate, exactly
 *  where it was called before this phase. `nonce_record` is the other
 *  half and runs after that handler's committee gate.
 *
 *  An entry that is past its TTL but has not been swept yet still counts
 *  as a replay. That is the conservative answer and it is nearly
 *  unobservable: the freshness window above refuses frames older than
 *  300 s anyway, and the two bounds differ only on the boundary second
 *  (`now - ts >= 300` versus `ts + 300 < now`). Answering "not a replay"
 *  there would be the only direction that can lose a refusal.
 *
 *  @return true if the frame must be dropped (stale timestamp, or this
 *          (sender, nonce) has already been recorded). */
static bool is_replay(const uint8_t *sender_id, uint64_t nonce,
                       uint64_t timestamp) {
    uint64_t now = (uint64_t)time(NULL);

    /* Reject messages outside ±5 minute window. Pre-existing gate, kept
     * verbatim; its time(NULL) is out of this phase's scope (see the
     * section header). */
    if (timestamp > now + 300 || timestamp + 300 < now)
        return true;

    uint32_t bucket = nonce_hash_fn(sender_id, nonce);

    for (nonce_node_t *n = nonce_buckets[bucket]; n; n = n->next) {
        if (n->nonce == nonce &&
            memcmp(n->sender_id, sender_id, NODUS_T3_WITNESS_ID_LEN) == 0)
            return true;
    }
    return false;
}

/** THE RECORD — the only writer.
 *
 *  MUST be called only after the calling handler's chain_id AND
 *  committee gates have passed, and before its first state mutation.
 *  Idempotent: recording an already-present (sender, nonce) is a no-op,
 *  so a handler that is reached twice on one frame cannot double-charge
 *  the sender's budget. */
static void nonce_record(const uint8_t *sender_id, uint64_t nonce,
                          uint64_t timestamp) {
    uint64_t now = (uint64_t)time(NULL);
    uint32_t bucket = nonce_hash_fn(sender_id, nonce);

    /* Expired entries in THIS bucket go first — they are free capacity
     * for every sender that hashes here. */
    nonce_evict_bucket(bucket, now);

    for (nonce_node_t *n = nonce_buckets[bucket]; n; n = n->next) {
        if (n->nonce == nonce &&
            memcmp(n->sender_id, sender_id, NODUS_T3_WITNESS_ID_LEN) == 0)
            return;
    }

    nonce_sender_t *s = nonce_sender_claim(sender_id);

    if (s->count >= NONCE_MAX_PER_SENDER) {
        nonce_sender_sweep(s, now);                  /* pass 1 — expired */
        if (s->count >= NONCE_MAX_PER_SENDER)
            nonce_sender_evict_oldest(s);            /* pass 2 — its own */
    }

    /* Insert at head (no mutex needed — single-threaded epoll). The
     * bucket head is re-read HERE because the two passes above may have
     * freed a node in this same chain. */
    nonce_node_t *node = malloc(sizeof(nonce_node_t));
    if (node) {
        memcpy(node->sender_id, sender_id, NODUS_T3_WITNESS_ID_LEN);
        node->nonce     = nonce;
        node->timestamp = timestamp;
        node->seq       = nonce_seq_next++;
        node->next      = nonce_buckets[bucket];
        nonce_buckets[bucket] = node;
        s->count++;
        s->last_seq = node->seq;
    }
}

/* ── Chain ID validation ─────────────────────────────────────────── */

/**
 * CRITICAL-2: Verify message chain_id matches our configured chain_id.
 * Prevents cross-zone replay attacks when multi-zone is enabled.
 *
 * O15L DG-1 (G1, G2) — THE DECISION IS A TOTAL FUNCTION OF
 * (w->chain_id, w->db), not a single all-zero escape hatch:
 *
 *   chain_id != 0, db != NULL   healthy, chain known    -> ENFORCE
 *   chain_id != 0, db == NULL   open failed, id kept    -> ENFORCE
 *   chain_id == 0, db == NULL   genuine pre-genesis     -> EXEMPT
 *   chain_id == 0, db != NULL   invariant violation     -> FAIL CLOSED
 *
 * The old form exempted the check whenever the local chain_id was
 * all-zero, and a node could hold a zeroed id while running (O15K). That
 * made the ABSENCE of an answer an answer that PERMITS — the shape that
 * forks a chain — and it switched off cross-chain replay protection on
 * precisely the node least able to notice.
 *
 * ⚠ THE IDENTITY IS THE AUTHORITY; the handle only disambiguates a ZERO
 * identity. nodus/BUGS.md option B proposed testing `w->db == NULL`
 * directly. Applied literally that INVERTS O15K fix A
 * (nodus_witness.c:685, the id installed before the open): a node whose
 * open failed holds exactly (db == NULL, chain_id != 0) — the state fix A
 * exists to produce — and a bare `db == NULL -> exempt` re-exempts that
 * very node. Row 2 must ENFORCE.
 *
 * Row 3 is the ONLY exemption and is deliberately kept (O15L §8, Q1 ->
 * option 1). It is structurally load-bearing: genesis flows through these
 * same handlers, so a node holding no chain must accept those frames or
 * no chain can ever start. The residual cross-chain replay window that
 * leaves open for a still-pre-genesis node is accepted risk, recorded
 * rather than hidden.
 *
 * Row 4 is unreachable through the ordinary open paths (every failure
 * exit of witness_db_open_path closes and NULLs the handle), but it IS
 * reachable for anyone who can write the data directory: a planted
 * witness_000...0.db parses as a valid name and yields set_chain_id(0)
 * on a SUCCESSFUL open. That is why the arm is kept rather than treated
 * as dead code.
 *
 * Cost: the healthy path is the same single 32-byte memcmp as before;
 * the pointer test is reached only when that memcmp says zero, i.e.
 * never on a chain past genesis.
 */
/* Non-static so test_v2_restart_gate.c can pin the DG-1 matrix directly.
 * Same rationale as the other de-staticed BFT primitives (see the header
 * block of nodus_witness_bft_internal.h): static + test linkage do not
 * compose under CMake's normal flow, and the protection is "no
 * production-facing header references it" rather than the qualifier.
 *
 * O15L Faz 5 — the canonical prototype now lives in
 * nodus_witness_bft_internal.h and test_v2_restart_gate.c includes it
 * rather than repeating it, so the test's calls are compiler-checked
 * against one declaration. The check is ASYMMETRIC and this comment will
 * not pretend otherwise: THIS translation unit does NOT include that
 * header. The header's #error gate demands NODUS_WITNESS_INTERNAL_API,
 * which the build system attaches to test executables via
 * target_compile_definitions and to no library target — the single
 * library TU that has the macro, nodus_witness_fault.c, #defines it for
 * itself under QGP_FAULT_INJECT, so reaching in is never silent, it has
 * to be asked for in the open — and whose name CMakeLists.txt turns into
 * a FATAL_ERROR if it is set as a CMake variable in a Release configure.
 * The same avoidance is why the Phase 6 commit wrappers near the top of
 * this file carry hand-written forward declarations. Consequence: changing this
 * signature breaks the TEST's compile — the intended alarm — but nothing
 * makes the definition and the header agree; that pairing is still a
 * review obligation. */
bool verify_chain_id(nodus_witness_t *w, const uint8_t *msg_chain_id) {
    static const uint8_t zero[32] = {0};

    if (memcmp(w->chain_id, zero, 32) != 0) {
        /* Rows 1 and 2 — we hold an identity, so we enforce it, whatever
         * state the database handle happens to be in. */
        if (memcmp(w->chain_id, msg_chain_id, 32) == 0) return true;
        fprintf(stderr, "%s: chain_id mismatch — rejecting message\n", LOG_TAG);
        return false;
    }

    /* Row 3 — no identity AND no chain database: genuine pre-genesis. */
    if (!w->db) return true;

    /* Row 4 — a zeroed identity with an OPEN chain database is not a
     * state to reason from. Fail closed, loudly. */
    fprintf(stderr,
            "%s: INVARIANT VIOLATION — chain_id is all-zero while the "
            "chain database is OPEN. This node cannot establish which "
            "chain it is on; refusing every BFT message.\n", LOG_TAG);
    return false;
}

/* ── Nonce generation ────────────────────────────────────────────── */

static uint64_t generate_nonce(void) {
    uint64_t nonce;
    /* CRITICAL-3: Abort on RNG failure — no weak fallback */
    if (nodus_random((uint8_t *)&nonce, sizeof(nonce)) != 0) {
        fprintf(stderr, "%s: FATAL: Cannot generate secure nonce\n", LOG_TAG);
        abort();
    }
    return nonce;
}

/* ── F17 A2: committee helpers ───────────────────────────────────────
 *
 * Under F17 consensus authority comes from the chain-derived committee,
 * not the gossip roster. These helpers centralize the lookup + pubkey-
 * based membership checks used by is_leader, handle_propose, handle_vote
 * and the round-start path.
 *
 * The committee accessor (nodus_committee_get_for_block) hits a
 * per-epoch cache, so repeated calls within the same epoch are O(1).
 * ──────────────────────────────────────────────────────────────────── */

/** Find a pubkey in a committee array. Returns the slot index or -1. */
static int committee_find_pubkey(const nodus_committee_member_t *arr,
                                   int count, const uint8_t *pk) {
    if (!arr || !pk) return -1;
    for (int i = 0; i < count; i++) {
        if (memcmp(arr[i].pubkey, pk, DNAC_PUBKEY_SIZE) == 0) return i;
    }
    return -1;
}

/** Load the committee authoritative for a given block height.
 *
 * F17 A5 — pre-genesis the chain DB is not yet created (w->db == NULL),
 * so nodus_committee_get_for_block would return -1. Treat that case
 * as "empty committee" (count=0, rc=0) so callers can take the
 * gossip-roster bootstrap fallback. This matches the semantic
 * "no on-chain validator set exists yet."
 *
 * ── O15L Faz 4 / F-9 — A MISSING HANDLE IS NOT ALWAYS PRE-GENESIS ─────
 *
 * `!w->db` used to mean exactly one thing here, and it does not. The
 * O15L DG-1 matrix separates two nodes that both hold a NULL handle:
 *
 *   (chain_id == 0, db == NULL)  genuine pre-genesis. There is no chain,
 *                                so "no committee" is a true, committed
 *                                ANSWER, and the gossip-roster bootstrap
 *                                fallback at every consumer is the
 *                                documented authorization (F17 A5). This
 *                                arm is preserved BYTE-IDENTICALLY.
 *
 *   (chain_id != 0, db == NULL)  DG-1 row 2 — a node that HOLDS a chain
 *                                and cannot read it. This is the state
 *                                O15K's fix A deliberately produces (the
 *                                identity is installed before the open,
 *                                nodus_witness.c, so a failed open keeps
 *                                it). Answering "count 0" for that node
 *                                handed it the transport roster as
 *                                consensus-membership authority at every
 *                                consumer below — G4's exact prohibition,
 *                                reached through the one door Faz 4's
 *                                five gates do not guard. It is not an
 *                                answer; it is the ABSENCE of one.
 *
 * Sequencing note: this separation is INERT until those five consumers
 * fail closed on rc != 0, which is why it lands with them rather than
 * with the Faz 1 matrix it derives from.
 *
 * The refusal is not logged here on purpose: this is a predicate called
 * from a tick-rate path (nodus_witness_bft_is_leader), and every consumer
 * that ACTS on the -1 prints its own line naming the site, the height and
 * — via the `w->db` suffix — this cause. One diagnosis per decision, not
 * one per query.
 *
 * @return 0 on success (count_out populated, possibly 0 for genuine
 *         pre-genesis or an empty validator table), -1 on DB error or on
 *         a chain this node holds but cannot read. */
static int load_committee_at_height(nodus_witness_t *w,
                                      uint64_t block_height,
                                      nodus_committee_member_t *out,
                                      int max_entries,
                                      int *count_out) {
    static const uint8_t zero_chain[32] = {0};

    if (!w || !out || !count_out) return -1;
    *count_out = 0;
    if (!w->db) {
        /* Same 32-byte comparison verify_chain_id makes, so the two gates
         * cannot disagree about which row of the matrix a node is in. */
        if (memcmp(w->chain_id, zero_chain, 32) == 0)
            return 0;       /* genuine pre-genesis: no chain, no committee */
        return -1;          /* DG-1 row 2: holds a chain, cannot read it */
    }
    return nodus_committee_get_for_block(w, block_height, out,
                                           max_entries, count_out);
}

/** Heap-allocating form of load_committee_at_height (S3).
 *
 * A DNAC_MAX_ACTIVE_VALIDATORS committee array is ~334 KB, so it cannot
 * live on the stack. Every consumer in this file that used to declare
 * `nodus_committee_member_t committee[DNAC_COMMITTEE_SIZE]` uses this
 * instead; the sizing decision then exists in exactly one place.
 *
 * On success *members_out is a calloc'd DNAC_MAX_ACTIVE_VALIDATORS-entry
 * array the caller MUST free() on EVERY path (count 0 included — the
 * pre-genesis case still returns 0 with an allocated buffer). On failure
 * *members_out is NULL and there is nothing to free.
 *
 * @return 0 on success (count may be 0 pre-genesis), -1 on error. */
static int load_committee_at_height_alloc(nodus_witness_t *w,
                                            uint64_t block_height,
                                            nodus_committee_member_t **members_out,
                                            int *count_out) {
    if (!members_out || !count_out) return -1;
    *members_out = NULL;
    *count_out   = 0;
    if (!w) return -1;

    nodus_committee_member_t *members =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*members));
    if (!members) return -1;

    int count = 0;
    if (load_committee_at_height(w, block_height, members,
                                   DNAC_MAX_ACTIVE_VALIDATORS, &count) != 0) {
        free(members);
        return -1;
    }
    *members_out = members;
    *count_out   = count;
    return 0;
}

/** Recompute w->bft_config from the committee for `block_height`.
 *
 * Authoritative source for quorum/f_tolerance. Replaces the legacy
 * gossip-roster-driven bft_config_init called from roster_add /
 * epoch-tick paths.
 *
 * F17 A5 bootstrap — if the committee is empty (chain has no
 * validators yet, i.e. pre-genesis) the function falls back to the
 * gossip-roster-derived quorum. This is ONLY reachable for the
 * genesis consensus round itself; once genesis commits and inserts
 * initial_validators into the validators table, subsequent rounds
 * always see a populated committee. Genesis security comes from
 * genesis_verify (Rule P — distinct pubkeys, supply invariant) +
 * honest-majority, not from committee gating.
 *
 * @return 0 on success (consensus_active may be true or false based on
 *         config state), -1 on DB error (w->bft_config left
 *         untouched, caller should fail-closed). */
int refresh_bft_config_from_committee(nodus_witness_t *w,
                                       uint64_t block_height) {
    if (!w) return -1;
    nodus_committee_member_t *committee = NULL;
    int count = 0;
    if (load_committee_at_height_alloc(w, block_height, &committee,
                                         &count) != 0) {
        return -1;
    }
    free(committee);   /* only the SIZE is needed here */
    if (count == 0) {
        /* F17 A5 bootstrap — pre-genesis fallback to gossip roster. */
        nodus_witness_bft_config_init(&w->bft_config,
                                        w->roster.n_witnesses);
    } else {
        nodus_witness_bft_config_init(&w->bft_config, (uint32_t)count);
    }
    return 0;
}

/* ── Config ──────────────────────────────────────────────────────── */

void nodus_witness_bft_config_init(nodus_witness_bft_config_t *cfg,
                                     uint32_t n) {
    if (!cfg) return;

    /* S3 — clamp at the release ceiling, not at DNAC_COMMITTEE_SIZE.
     *
     * The clamp exists so quorum can never exceed the number of vote
     * slots that physically exist; those arrays are now
     * DNAC_MAX_ACTIVE_VALIDATORS-sized (nodus_witness.h round_state), so
     * that is the correct bound. Clamping at 7 would have been WRONG once
     * the active set can be larger: a 9-member set would have produced
     * quorum(7) = 5 instead of quorum(9) = 7, i.e. a quorum smaller than
     * 2f+1 for the real set — a safety break, not just a liveness quirk.
     *
     * n = 7 → 5 and n = 9 → 7; the live 7-node cluster is unaffected. */
    if (n > DNAC_MAX_ACTIVE_VALIDATORS) n = DNAC_MAX_ACTIVE_VALIDATORS;

    cfg->n_witnesses = n;

    /* Below minimum — consensus disabled.
     *
     * ── THIS DISAGREES WITH dna_bft_quorum, AND THE DISAGREEMENT IS
     * DELIBERATE. DO NOT "FIX" IT.
     *
     * For the same n the two functions answer differently — n=4 gives
     * dna_bft_quorum(4) = 3 (shared/dnac/ledger_ids.h:110) and 0 here —
     * because they are answering different questions. dna_bft_quorum is
     * the PURE FORMULA: "if a set of n validators were to decide
     * something, how many would that take". This function additionally
     * decides WHETHER THIS NODE PARTICIPATES AT ALL, and below
     * NODUS_T3_MIN_WITNESSES the answer is no. The 0 it writes is not a
     * threshold that happens to be small; it is the sentinel
     * nodus_witness_bft_consensus_active reads, and it MUST stay 0.
     *
     * Reconciling them — making this return dna_bft_quorum(n) for small n
     * — would silently re-enable consensus on a cluster too small to be
     * safe. Making dna_bft_quorum return 0 below the minimum would corrupt
     * every historical-committee threshold derived from it, which is
     * asked about a set that HAS decided, not about this node.
     *
     * ⚠ THE 0 IS A SENTINEL, SO EVERY `<` AGAINST IT IS VACUOUS. That is
     * the O15O Faz 2 defect class: `x < 0` is false for all x, so an
     * unguarded threshold test at quorum 0 SUCCEEDS on any input. Six
     * sites in this tree had to be guarded for that reason — the vote
     * quorum and the view-change quorum in this file, the prepared-cert
     * threshold, the NEW_VIEW reproposal sig count, and both the
     * fork-detection and sync-cert thresholds in nodus_witness_sync.c.
     * Any NEW comparison against bft_config.quorum must handle 0
     * explicitly; the sentinel will not do it for you. */
    if (n < NODUS_T3_MIN_WITNESSES) {
        cfg->f_tolerance = 0;
        cfg->quorum = 0;
        cfg->round_timeout_ms = 0;
        cfg->viewchg_timeout_ms = 0;
        return;
    }

    /* Phase 8 / Task 8.1 — derive the quorum from n directly via the
     * standard PBFT safety formula (2n)/3 + 1, and keep f_tolerance as
     * informational only.
     *
     * The old formula 2*f + 1 with f = (n-1)/3 was UNSAFE for cluster
     * sizes where n ∉ {3f+1}. Example: n=5 → f=(5-1)/3=1 → q=3. Two
     * disjoint quorums of 3 from a 5-witness cluster can overlap on
     * just 1 witness — NOT > f, which means both quorums can be
     * simultaneously honest-majority while disagreeing. (2n)/3+1 gives
     * q=4 for n=5, restoring the >f intersection guarantee.
     *
     * Production cluster (n=7) is unaffected — both formulas give q=5.
     * Only n=5, 8, 11, ... see a value change. See Phase 8 release
     * notes; this is a silent security upgrade.
     *
     * ── S3 INVARIANT: ONE VALIDATOR, ONE VOTE ─────────────────────────
     * `n` is a COUNT of active validators. Neither the quorum nor any
     * vote tally anywhere in this file is weighted by stake: quorum is a
     * pure function of n, and handle_vote increments approve_count by 1
     * per distinct committee pubkey. Stake (self_stake, total_stake,
     * external_delegated) is read ONLY for committee RANKING
     * (nodus_witness_committee.c), reward SETTLEMENT
     * (apply_epoch_settlement) and the supply invariant — never on a
     * voting or quorum path. Introducing stake weight here would turn a
     * BFT safety threshold into a plutocratic one and silently break the
     * 2f+1 intersection argument above. Identical to dna_bft_quorum in
     * shared/dnac/ledger_ids.h. */
    cfg->f_tolerance = (n - 1) / 3;
    cfg->quorum = (2 * n) / 3 + 1;

    /* Timeouts */
    cfg->round_timeout_ms = NODUS_T3_ROUND_TIMEOUT_MS;
    cfg->viewchg_timeout_ms = NODUS_T3_VIEWCHG_TIMEOUT_MS;
}

bool nodus_witness_bft_consensus_active(const nodus_witness_t *w) {
    return w && w->bft_config.quorum > 0;
}

/* ── Leader election ─────────────────────────────────────────────── */

int nodus_witness_bft_leader_index(uint64_t epoch, uint32_t view, int n) {
    if (n <= 0) return -1;
    return (int)((epoch + view) % (uint64_t)n);
}

bool nodus_witness_bft_is_leader(nodus_witness_t *w) {
    if (!w) return false;

    /* O15E Faz D — a pinned-genesis joiner still fetching/deriving its
     * genesis (no committed chain yet) is never a leader. Defence in
     * depth: such a node is not in any committee either, so is_leader
     * would already return false — but this makes the role-safety
     * invariant explicit and independent of committee resolution. */
    if (w->v2_join.active) return false;

    /* F17 A3 — leader is determined by the chain-derived committee for
     * the next block. F17 A5 bootstrap — if committee empty (pre-
     * genesis), fall back to gossip roster. */
    /* ── O15O Faz 1 — A DB FAULT IS NOT HEIGHT 0.
     *
     * The height read below picks the committee AND, through
     * `epoch = next_bh / DNAC_EPOCH_LENGTH`, the leader index. Answering
     * 0 on a failed read used to resolve the committee for height 1 at
     * epoch 0 — on a chain that may be thousands of blocks along — so a
     * node with a transient DB fault could conclude it was the leader and
     * PROPOSE. Same conclusion, same cost, same log shape as the
     * committee fault immediately below: liveness only, never safety. */
    uint64_t tip_h = 0;
    if (nodus_witness_block_height_checked(w, &tip_h) != 0) {
        fprintf(stderr,
                "%s: is_leader — CANNOT READ THE CHAIN HEIGHT; refusing to "
                "lead rather than electing a leader for height 1\n",
                LOG_TAG);
        return false;
    }
    uint64_t next_bh = tip_h + 1;
    nodus_committee_member_t *committee = NULL;
    int count = 0;
    int my_idx = -1;
    int lc_rc = load_committee_at_height_alloc(w, next_bh, &committee, &count);
    if (lc_rc != 0) {
        /* ── O15L Faz 4 / DG-4 / G4 — A FAULT IS NOT AN EMPTY COMMITTEE.
         *
         * This used to share the `else` below, so a node that could not
         * READ its committee elected a leader from the gossip roster —
         * and if the sorted rank happened to land on itself, it PROPOSED.
         * A node that cannot establish who is entitled to lead must not
         * lead. Mirrors the shipped VOTE gate (O15J Block 2A, below).
         *
         * Cost is liveness, never safety: a node that declines to lead
         * simply produces no proposal, and the round rotates to a peer
         * that can — which is the same outcome as a node being down.
         *
         * ⚠ VOLUME. Unlike the four message-handler gates below, this one
         * is evaluated on EVERY witness tick (nodus_witness.c, the block
         * timer), so a persistent fault prints on every tick. That is
         * deliberate and it is the requirement: F-10 records that a silent
         * fail-closed reproduces the "silent death" class O15K removed,
         * and this node has stopped participating in consensus — the one
         * thing an operator must not have to infer from an absence. */
        free(committee);
        fprintf(stderr,
                "%s: is_leader — CANNOT ESTABLISH THE COMMITTEE at height "
                "%llu (rc=%d%s); refusing to lead rather than electing a "
                "leader from the transport roster\n",
                LOG_TAG, (unsigned long long)next_bh, lc_rc,
                w->db ? "" : ", chain database not open");
        return false;
    }
    if (count > 0) {
        my_idx = committee_find_pubkey(committee, count,
                                         w->server->identity.pk.bytes);
        free(committee);
        committee = NULL;
    } else {
        free(committee);
        committee = NULL;
        /* rc == 0 && count == 0 — genuinely pre-genesis: a committed
         * answer that there is no committee yet. Gossip-roster-based
         * leader selection, unchanged. Only active for the genesis round
         * itself. SORTED rank, not arrival index — the roster is
         * arrival-ordered between epoch rebuilds, and two nodes with the
         * same set but different arrival orders would disagree on the
         * leader (BUGS.md 2026-08-04). */
        count = (int)w->roster.n_witnesses;
        my_idx = nodus_witness_roster_sorted_find(&w->roster, w->my_id);
    }

    if (my_idx < 0 || count <= 0) return false;
    /* C7 fix: block-height epoch — cluster-agreed, no clock-skew fork risk */
    uint64_t epoch = next_bh / (uint64_t)DNAC_EPOCH_LENGTH;
    int leader = nodus_witness_bft_leader_index(epoch, w->current_view,
                                                  count);
    return leader == my_idx;
}

/* ── Roster ──────────────────────────────────────────────────────── */

int nodus_witness_roster_find(const nodus_witness_roster_t *roster,
                                const uint8_t *witness_id) {
    if (!roster || !witness_id) return -1;

    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        if (memcmp(roster->witnesses[i].witness_id, witness_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return (int)i;
    }
    return -1;
}

int nodus_witness_roster_sorted_find(const nodus_witness_roster_t *roster,
                                       const uint8_t *witness_id) {
    if (!roster || !witness_id) return -1;
    if (nodus_witness_roster_find(roster, witness_id) < 0) return -1;

    /* Rank in the SET, not the array: count of strictly-smaller ids.
     * Ids are unique (roster_add dup-checks), so no tie-break needed.
     * O(n) over NODUS_T3_MAX_WITNESSES — same cost class as the linear
     * roster_find above. */
    int rank = 0;
    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        if (memcmp(roster->witnesses[i].witness_id, witness_id,
                   NODUS_T3_WITNESS_ID_LEN) < 0)
            rank++;
    }
    return rank;
}

int nodus_witness_roster_sorted_at(const nodus_witness_roster_t *roster,
                                     int rank) {
    if (!roster || rank < 0 || (uint32_t)rank >= roster->n_witnesses)
        return -1;

    /* Inverse of nodus_witness_roster_sorted_find: the ARRAY index whose
     * id has exactly `rank` strictly-smaller ids in the set. Ids are
     * unique (roster_add dup-checks), so exactly one entry qualifies.
     * O(n^2) over NODUS_T3_MAX_WITNESSES, called only on the pre-genesis
     * forwarding fallback. */
    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        int r = 0;
        for (uint32_t j = 0; j < roster->n_witnesses; j++) {
            if (memcmp(roster->witnesses[j].witness_id,
                       roster->witnesses[i].witness_id,
                       NODUS_T3_WITNESS_ID_LEN) < 0)
                r++;
        }
        if (r == rank) return (int)i;
    }
    return -1;
}

int nodus_witness_roster_add(nodus_witness_t *w,
                               const nodus_witness_roster_entry_t *entry) {
    if (!w || !entry) return -1;

    if (w->roster.n_witnesses >= NODUS_T3_MAX_WITNESSES)
        return -1;

    /* Duplicate check */
    if (nodus_witness_roster_find(&w->roster, entry->witness_id) >= 0)
        return 0;

    memcpy(&w->roster.witnesses[w->roster.n_witnesses], entry,
           sizeof(nodus_witness_roster_entry_t));
    w->roster.n_witnesses++;
    w->roster.version++;

    /* F17 A4 — roster is now transport-only (peer discovery +
     * witness_id↔pubkey map). BFT config is refreshed from the chain
     * committee at round-start. No my_index tracking needed: self-
     * identity in consensus paths is resolved via
     * w->server->identity.pk against the committee pubkey list. */

    fprintf(stderr, "%s: roster add (now %u witnesses, transport)\n",
            LOG_TAG, w->roster.n_witnesses);
    return 0;
}

/* ── Fill T3 message header with identity ────────────────────────── */

/* PR 2 (2026-05-03) Option C — explicit-timestamp variant. Used by the
 * broadcast path for PROPOSE messages so the wire-carried timestamp
 * matches the leader's stored block timestamp exactly. Compile-time
 * enforced (callers cannot forget): broadcast() dispatches by msg->type
 * and only PROPOSE takes the explicit-ts path. See
 * docs/plans/2026-05-03-pr2-timestamp-determinism-impl.md. */
static void fill_header_with_ts(nodus_witness_t *w,
                                  nodus_t3_header_t *hdr,
                                  uint64_t ts) {
    hdr->version = NODUS_T3_BFT_PROTOCOL_VER;
    hdr->round = w->current_round;
    hdr->view = w->current_view;
    memcpy(hdr->sender_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    hdr->timestamp = ts;
    hdr->nonce = generate_nonce();
    memcpy(hdr->chain_id, w->chain_id, 32);
}

static void fill_header(nodus_witness_t *w, nodus_t3_header_t *hdr) {
    /* Default — operational wall-clock for non-block-storage messages
     * (PREVOTE, PRECOMMIT, COMMIT, sync_*, fwd_rsp, etc.). PROPOSE goes
     * through fill_header_with_ts via the broadcast dispatch. */
    fill_header_with_ts(w, hdr, (uint64_t)time(NULL));
}

/* ── Broadcast T3 message to all connected witness peers ─────────── */

int nodus_witness_bft_broadcast(nodus_witness_t *w, nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    /* PR 2 (2026-05-03) Option C — for PROPOSE messages, the wire
     * timestamp MUST equal the leader's authoritative
     * round_state.proposal_timestamp (captured once at start_round),
     * NOT a fresh time(NULL). Otherwise leader's stored block timestamp
     * differs from what followers extract from hdr.timestamp and store
     * (live bug: chain `e154cff9` EU-4 prev_hash divergence from
     * block 193). Followers' handle_propose copies hdr.timestamp into
     * round_state.proposal_timestamp (bft.c:3978); leader uses the
     * same field for its own commit_batch (bft.c:4524, 4534). With
     * this fix, leader and followers store the SAME value. */
    if (msg->type == NODUS_T3_PROPOSE) {
        fill_header_with_ts(w, &msg->header,
                              w->round_state.proposal_timestamp);
    } else {
        fill_header(w, &msg->header);
    }

    /* Set method string from type */
    const char *method = nodus_t3_type_to_method(msg->type);
    if (method)
        snprintf(msg->method, sizeof(msg->method), "%s", method);

    /* Encode (signs with our secret key).
     * Heap-allocated 1 MB buffer (NODUS_W_MAX_SYNC_RSP_SIZE) so that
     * PROPOSE for 8+ full-size TXs and COMMIT (which bundles batch_txs +
     * cert array) fit. The 128 KB NODUS_T3_MAX_MSG_SIZE is too small
     * for those — leader silently fails to broadcast under load.
     * Receiver verify uses the same cap (nodus_t3_verify). */
    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) {
        fprintf(stderr, "%s: malloc failed for T3 %s encode\n",
                LOG_TAG, msg->method);
        return -1;
    }
    size_t len = 0;

    if (nodus_t3_encode(msg, &w->server->identity.sk,
                         buf, NODUS_W_MAX_SYNC_RSP_SIZE, &len) != 0) {
        fprintf(stderr, "%s: failed to encode T3 %s\n",
                LOG_TAG, msg->method);
        free(buf);
        return -1;
    }

    /* Send to all connected identified peers */
    int sent = 0;
    for (int i = 0; i < w->peer_count; i++) {
        if (w->peers[i].conn && w->peers[i].identified) {
            if (nodus_tcp_send(w->peers[i].conn, buf, len) == 0)
                sent++;
        }
    }

    free(buf);
    return sent;
}

/* ── Commit to database ──────────────────────────────────────────── */

/**
 * Update UTXO set from committed transaction data.
 *
 * Parses the serialized transaction to extract outputs, then:
 *   - SPEND: removes spent UTXOs (by input nullifiers)
 *   - ALL: adds new output UTXOs (computing nullifier from fingerprint + seed)
 *
 * Called inside the same SQLite transaction as nullifier/genesis writes.
 *
 * DNAC v1 wire format (outputs section):
 *   Header: version(1) + type(1) + timestamp(8) + tx_hash(64) = 74
 *   Inputs: count(1) + [nullifier(64) + amount(8)] * N
 *   Outputs: count(1) + [version(1) + fingerprint(129) + amount(8) + seed(32) + memo_len(1) + memo(n)] * M
 */

/* ── Derive chain_id = SHA3-256(fp_bytes || tx_hash) ─────────────── */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Derive chain_id from genesis fingerprint and tx_hash.
 * chain_id = SHA3-256( fp_bytes(64) || tx_hash(64) )
 *
 * @param genesis_fp  128-char hex fingerprint string
 * @param tx_hash     64-byte transaction hash
 * @param chain_id_out 32-byte output buffer
 * @return 0 on success, -1 on error
 */
static int nodus_derive_chain_id(const char *genesis_fp,
                                  const uint8_t *tx_hash,
                                  uint8_t *chain_id_out) {
    if (!genesis_fp || !tx_hash || !chain_id_out) return -1;

    size_t fp_len = strnlen(genesis_fp, 129);
    if (fp_len != 128) {
        fprintf(stderr, "%s: derive_chain_id: bad fingerprint len %zu\n",
                LOG_TAG, fp_len);
        return -1;
    }

    /* Convert hex fingerprint to 64 binary bytes */
    uint8_t fp_bytes[64];
    for (size_t i = 0; i < 64; i++) {
        int hi = hex_nibble(genesis_fp[i * 2]);
        int lo = hex_nibble(genesis_fp[i * 2 + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "%s: derive_chain_id: invalid hex at pos %zu\n",
                    LOG_TAG, i * 2);
            return -1;
        }
        fp_bytes[i] = (uint8_t)((hi << 4) | lo);
    }

    /* Concatenate: fp_bytes(64) || tx_hash(64) = 128 bytes */
    uint8_t data[64 + NODUS_T3_TX_HASH_LEN];
    memcpy(data, fp_bytes, 64);
    memcpy(data + 64, tx_hash, NODUS_T3_TX_HASH_LEN);

    if (qgp_sha3_256(data, sizeof(data), chain_id_out) != 0)
        return -1;

    /* Canonical chain_id layout: the first 16 bytes (128 bits) are the
     * authoritative identifier; bytes 16-31 are ALWAYS zero. This matches
     * the format produced by witness_scan_chain_db on restart (which only
     * parses 16 bytes out of the filename) so both paths converge on the
     * same in-memory value. Without this, a live-genesis node ends up
     * with full-32-byte chain_id in memory while a restarted node has
     * 16-byte + 16-zero, causing bogus CHAIN_QUORUM dissent and sticky
     * quarantine that blocks forwarded dnac_spend requests from ever
     * reaching the leader's handler. */
    memset(chain_id_out + 16, 0, 16);
    return 0;
}

/* O15G — parse the first-recipient fingerprint out of a serialized genesis TX
 * and derive its chain_id. This is the EXACT walk + derivation commit_genesis
 * performs inline when bootstrapping a fresh chain DB (below, if(!w->db));
 * factored out so the genesis sync leg can re-derive the synced genesis's
 * chain_id and cross-check it against the DISCOVER-agreed chain the joiner
 * bootstrapped onto (commit_genesis SKIPS that check when w->db is already
 * set). Pure wire walk, no state. Declared in nodus_witness.h. */
int nodus_witness_genesis_derive_chain_id(const uint8_t *tx_data,
                                          uint32_t tx_len,
                                          const uint8_t *tx_hash,
                                          uint8_t *out_chain_id) {
    if (!tx_data || !tx_hash || !out_chain_id) return -1;
    if (tx_len < DNAC_TX_HEADER_SIZE + 3 + 129) {
        fprintf(stderr, "%s: genesis tx_data too short for fingerprint (len=%u)\n",
                LOG_TAG, tx_len);
        return -1;
    }
    size_t fp_off = DNAC_TX_HEADER_SIZE;
    uint8_t in_count = tx_data[fp_off++];
    fp_off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);
    if (fp_off >= tx_len) return -1;
    uint8_t out_count = tx_data[fp_off++];
    if (out_count == 0 || fp_off + 1 + 129 > tx_len) return -1;
    fp_off += 1;  /* output version byte */
    const char *genesis_fp = (const char *)(tx_data + fp_off);
    return nodus_derive_chain_id(genesis_fp, tx_hash, out_chain_id);
}

/* v0.16 stage C.3 — TX-type-aware fee burn helper.
 *
 * In v0.16 the reward system moved from "fees pooled + redistributed"
 * (accumulator model) to "fees burn immediately + rewards come from
 * inflation mint" (push-settlement model). route_tx_fee is the single
 * destination for every TX's committed_fee — it always adds to
 * supply_tracking.total_burned, regardless of tx_type.
 *
 * The tx_type parameter is kept in the signature for future variants
 * (e.g. per-type burn fraction); today it is intentionally unused.
 *
 * @param w            witness context (DB must be open)
 * @param tx_type      NODUS_W_TX_* (unused in v0.16 — see above)
 * @param committed_fee  fee amount in raw DNAC units (may be 0)
 * @param tx_hash      tx_hash the fee came from (for the
 *                     supply_tracking.last_tx_hash audit trail)
 * @return 0 on success or no-op (fee == 0), -1 on overflow / DB error
 */
static int route_tx_fee(nodus_witness_t *w, uint32_t tx_type,
                          uint64_t committed_fee, const uint8_t *tx_hash) {
    (void)tx_type;
    if (committed_fee == 0) return 0;
    return nodus_witness_supply_add_burned(w, committed_fee, tx_hash);
}

static int update_utxo_set(nodus_witness_t *w,
                              const uint8_t *tx_hash,
                              uint8_t tx_type,
                              const uint8_t *const *nullifiers,
                              uint8_t nullifier_count,
                              const uint8_t *tx_data,
                              uint32_t tx_len,
                              uint64_t *fee_out) {
    /* v2 wire: need at least the 82-byte header + 1 input_count byte. */
    if (!tx_data || tx_len < DNAC_TX_HEADER_SIZE + 1) {
        fprintf(stderr, "%s: update_utxo_set: invalid tx_data (ptr=%p len=%u)\n",
                LOG_TAG, (void *)tx_data, tx_len);
        return -1;
    }

    /* For SPEND: remove spent UTXOs by input nullifiers */
    if (tx_type != NODUS_W_TX_GENESIS) {
        for (int i = 0; i < nullifier_count; i++) {
            nodus_witness_utxo_remove(w, nullifiers[i]);
        }
    }

    /* Parse to output section.
     * v2 header (82 B): version(1) + type(1) + timestamp(8) + tx_hash(64) + committed_fee(8) */
    size_t offset = DNAC_TX_HEADER_SIZE;
    if (offset >= tx_len) {
        fprintf(stderr, "%s: update_utxo_set: tx_data too short for inputs (len=%u)\n",
                LOG_TAG, tx_len);
        return -1;
    }

    /* Parse inputs and sum their amounts (for fee calculation) */
    uint8_t input_count = tx_data[offset++];
    uint64_t total_input = 0;
    for (int i = 0; i < input_count; i++) {
        offset += NODUS_T3_NULLIFIER_LEN;  /* skip nullifier (64) */
        if (offset + 8 + 64 > tx_len) {
            fprintf(stderr, "%s: update_utxo_set: input %d truncated at amount/token_id\n",
                    LOG_TAG, i);
            return -1;
        }
        uint64_t in_amt;
        memcpy(&in_amt, tx_data + offset, 8);
        total_input += in_amt;
        offset += 8;   /* amount */
        offset += 64;  /* token_id */
    }

    /* Read output count */
    if (offset >= tx_len) {
        fprintf(stderr, "%s: update_utxo_set: tx_data truncated at outputs (offset=%zu len=%u)\n",
                LOG_TAG, offset, tx_len);
        return -1;
    }
    uint8_t output_count = tx_data[offset++];
    if (output_count > NODUS_T3_MAX_TX_OUTPUTS) {
        fprintf(stderr, "%s: update_utxo_set: output_count %u exceeds max %d\n",
                LOG_TAG, output_count, NODUS_T3_MAX_TX_OUTPUTS);
        return -1;
    }

    /* O15O Faz 1 — the height stamped on every UTXO row this function
     * writes. A fault answering 0 would create the outputs at height 1,
     * where the locked-UTXO cutoff (nodus_witness_verify.c Rule D) and
     * every later height comparison read them. Refuse instead. */
    uint64_t utxo_tip = 0;
    if (nodus_witness_block_height_checked(w, &utxo_tip) != 0) {
        fprintf(stderr, "%s: update_utxo_set: chain-height read faulted — "
                "refusing to stamp outputs at height 1\n", LOG_TAG);
        return -1;
    }
    uint64_t block_height = utxo_tip + 1;
    int stored = 0;
    uint64_t total_output = 0;

    for (int i = 0; i < output_count; i++) {
        /* Minimum output: version(1) + fp(129) + amount(8) + token_id(64) + seed(32) + memo_len(1) = 235 */
        if (offset + 235 > tx_len) {
            fprintf(stderr, "%s: update_utxo_set: output %d truncated (need %zu, have %u)\n",
                    LOG_TAG, i, offset + 235, tx_len);
            return -1;
        }

        offset += 1;  /* output version */

        const char *fingerprint = (const char *)(tx_data + offset);
        offset += 129;  /* fingerprint (128 hex + null) */

        uint64_t amount;
        memcpy(&amount, tx_data + offset, 8);
        offset += 8;
        total_output += amount;

        /* Read token_id (64 bytes — zeros = native DNAC) */
        const uint8_t *output_token_id = tx_data + offset;
        offset += 64;

        const uint8_t *nullifier_seed = tx_data + offset;
        offset += 32;

        uint8_t memo_len = tx_data[offset++];
        if (offset + memo_len > tx_len) {
            fprintf(stderr, "%s: update_utxo_set: memo truncated at output %d\n",
                    LOG_TAG, i);
            return -1;
        }
        offset += memo_len;

        /* Compute nullifier = SHA3-512(fingerprint_str + nullifier_seed) */
        size_t fp_len = strnlen(fingerprint, 128);
        uint8_t nul_input[256];
        memcpy(nul_input, fingerprint, fp_len);
        memcpy(nul_input + fp_len, nullifier_seed, 32);

        nodus_key_t nul_hash;
        if (nodus_hash(nul_input, fp_len + 32, &nul_hash) != 0) {
            fprintf(stderr, "%s: update_utxo_set: hash failed for output %d\n",
                    LOG_TAG, i);
            return -1;
        }

        if (nodus_witness_utxo_add(w, nul_hash.bytes, fingerprint,
                                      amount, tx_hash, (uint32_t)i, block_height,
                                      output_token_id) == 0) {
            stored++;
        }
    }

    /* ── v0.17.1 fee routing: read committed_fee directly from TX wire ──
     *
     * Prior versions inferred `fee = total_input − total_output`, then
     * used a first-input-token_id proxy to guard against "token-as-fee"
     * paths (the `native_fee` bool). That proxy misfired on every token
     * SPEND (first input was the token UTXO, so the guard skipped the
     * burn — invariant hard gate rejected the block: see
     * dnac/docs/plans/2026-04-22-committed-fee-wire-field-design.md §1).
     *
     * v0.17.1 ships the explicit `committed_fee` wire field in the TX
     * header, hashed into the signed preimage. route_tx_fee burns it
     * unconditionally for every non-GENESIS TX. DELEGATE and UNDELEGATE
     * no longer absorb the fee into state amount — their `delegation_
     * amount` / `amount` type-specific fields are now independent wire
     * values (SB-1 debt closed).
     *
     * total_input/total_output remain computed above (still logged) for
     * operator visibility; the supply-invariant hard gate is the
     * authoritative consensus check.
     */
    uint64_t committed_fee = 0;
    if (tx_type != NODUS_W_TX_GENESIS) {
        if (dnac_tx_read_committed_fee(tx_data, tx_len, &committed_fee) != 0) {
            fprintf(stderr,
                    "%s: update_utxo_set: dnac_tx_read_committed_fee failed "
                    "(tx_type=%u, len=%u) — malformed or v1 wire\n",
                    LOG_TAG, (unsigned)tx_type, tx_len);
            return -1;
        }
        if (committed_fee > 0) {
            if (route_tx_fee(w, tx_type, committed_fee, tx_hash) != 0) {
                fprintf(stderr,
                        "%s: route_tx_fee failed (committed_fee=%llu)\n",
                        LOG_TAG, (unsigned long long)committed_fee);
                return -1;
            }
        }
    }

    if (fee_out) *fee_out = committed_fee;

    fprintf(stderr,
            "%s: UTXO set updated: -%d spent, +%d/%d outputs, fee=%llu (block %llu)\n",
            LOG_TAG,
            (tx_type != NODUS_W_TX_GENESIS) ? nullifier_count : 0,
            stored, output_count,
            (unsigned long long)committed_fee,
            (unsigned long long)block_height);
    (void)total_input;
    (void)total_output;
    return 0;
}

/**
 * Write committed transaction state to witness database.
 * Called for both local commit (PRECOMMIT quorum) and remote commit.
 *
 * Operations (atomic via SQLite transaction):
 *   - Genesis: record genesis state
 *   - Non-genesis: add all nullifiers
 *   - Update UTXO set (remove spent, add outputs)
 * After atomic block:
 *   - Add ledger entry (audit trail)
 *   - Create block
 */
/**
 * Inner commit logic: nullifiers, UTXO, TX store, ledger.
 * Does NOT manage DB transaction (caller handles begin/commit).
 * Does NOT create blocks (caller handles block_add).
 * Used by both single-TX commit_block() and batch commit path.
 *
 * @return 0 on success, -1 on failure (caller should rollback)
 */
/* Supply invariant check (Phase 3 / Task 3.0).
 *
 * Returns true if any of the following invariants is currently violated
 * for the live witness DB state:
 *
 *   1. Native DNAC: registered genesis_supply must equal the sum of all
 *      utxo_set rows whose token_id is the native (zero) token.
 *   2. Per custom token: the registered supply (from the `tokens` table)
 *      must equal the sum of utxo_set rows for that token_id.
 *
 * Burn fees are tracked separately and excluded from the comparison
 * (genesis_supply is the post-burn target).
 *
 * Read-only — does not modify w->db. Side effect: emits an ERROR log
 * line via QGP_LOG_ERROR with the specific delta that violated. Phase
 * 6 SAVEPOINT attribution replay relies on these log lines to identify
 * the offending TX in a batch.
 *
 * Lifted from the inline check in the legacy commit_block_inner so
 * Phase 3.4 can move the call from per-TX to per-block (run once
 * inside finalize_block) without changing the check's semantics.
 */
/* v0.16 Stage F.1 — HARD supply invariant check.
 *
 * Replaces the pre-v0.16 advisory invariant (which used the old
 * 16-DNAC halving curve). The new model is bookkeeping-closed:
 *
 *   expected = genesis_supply + total_minted − total_burned
 *   observed = Σ utxo_set.amount (native DNAC only)
 *            + Σ validator.self_stake
 *            + Σ validator.total_delegated
 *            + Σ epoch_state.epoch_pool_accum (current + any queued)
 *
 * Any mismatch is a consensus-critical bug and MUST reject the block.
 *
 * Returns 0 when the invariant holds (including pre-genesis state
 * where supply_tracking is empty — no supply to conserve yet); -1
 * when violated; also -1 on internal DB error so the block is
 * rejected rather than committed on stale/partial reads.
 *
 * D1 (2026-07-31): the "DB error → -1" half of that contract only
 * became real once nodus_witness_supply_get grew a third return value.
 * Before it, every failure looked like pre-genesis and the gate was
 * skipped outright.
 *
 * Read-only — does not mutate w->db.
 */
/* Non-static so test_witness_state_root_failclose.c can pin the D1 gate
 * directly. Same rationale as the other de-staticed BFT primitives (see
 * the header block of nodus_witness_bft_internal.h): static + test
 * linkage do not compose under CMake's normal flow, and the protection
 * is "no production-facing header references it" rather than the
 * qualifier. The canonical home for this prototype is
 * nodus_witness_bft_internal.h — that file was outside this change's
 * approved whitelist, so the test declares it locally instead. */
int check_supply_invariant_v016(nodus_witness_t *w) {
    if (!w || !w->db) return -1;

    nodus_witness_supply_t sup;
    memset(&sup, 0, sizeof(sup));
    int sup_rc = nodus_witness_supply_get(w, &sup);
    if (sup_rc < 0) {
        /* D1 (2026-07-31): a DB error is NOT pre-genesis. Skipping the
         * gate here would commit the block with the invariant unchecked
         * — the caller at finalize_block treats non-zero as REJECT. */
        QGP_LOG_ERROR(LOG_TAG,
            "SUPPLY INVARIANT: supply_get DB error — gate cannot run, "
            "rejecting block");
        return -1;
    }
    if (sup_rc == 1) {
        /* Pre-genesis: the supply_tracking row genuinely does not exist.
         * Nothing to conserve yet — genesis commit populates it. */
        return 0;
    }

    /* expected, guarded against overflow + underflow. */
    uint64_t expected = sup.genesis_supply;
    if (sup.total_minted > UINT64_MAX - expected) {
        QGP_LOG_ERROR(LOG_TAG,
            "SUPPLY INVARIANT: genesis+minted overflow genesis=%llu minted=%llu",
            (unsigned long long)sup.genesis_supply,
            (unsigned long long)sup.total_minted);
        return -1;
    }
    expected += sup.total_minted;
    if (sup.total_burned > expected) {
        QGP_LOG_ERROR(LOG_TAG,
            "SUPPLY INVARIANT: burned > genesis+minted (burned=%llu exp=%llu)",
            (unsigned long long)sup.total_burned,
            (unsigned long long)expected);
        return -1;
    }
    expected -= sup.total_burned;

    /* observed = utxo_native + validator_stakes + delegations + epoch_pool */
    uint64_t utxo_native = 0;
    if (nodus_witness_utxo_sum_by_token(w, NULL, &utxo_native) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "SUPPLY INVARIANT: utxo_sum_by_token failed");
        return -1;
    }

    uint64_t self_stake_sum = 0;
    uint64_t total_delegated_sum = 0;
    {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COALESCE(SUM(self_stake), 0), "
                "       COALESCE(SUM(total_delegated), 0) "
                "FROM validators",
                -1, &stmt, NULL) != SQLITE_OK) {
            /* Schema-missing in unit-test fixtures is acceptable; skip
             * these two terms (they'd be zero anyway). */
        } else {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                self_stake_sum      = (uint64_t)sqlite3_column_int64(stmt, 0);
                total_delegated_sum = (uint64_t)sqlite3_column_int64(stmt, 1);
            }
            sqlite3_finalize(stmt);
        }
    }

    uint64_t epoch_pool_sum = 0;
    {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT COALESCE(SUM(epoch_pool_accum), 0) FROM epoch_state",
                -1, &stmt, NULL) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                epoch_pool_sum = (uint64_t)sqlite3_column_int64(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
    }

    uint64_t observed = utxo_native;
    if (self_stake_sum > UINT64_MAX - observed) goto overflow_fail;
    observed += self_stake_sum;
    if (total_delegated_sum > UINT64_MAX - observed) goto overflow_fail;
    observed += total_delegated_sum;
    if (epoch_pool_sum > UINT64_MAX - observed) goto overflow_fail;
    observed += epoch_pool_sum;

    if (expected != observed) {
        QGP_LOG_ERROR(LOG_TAG,
            "SUPPLY INVARIANT VIOLATION: expected=%llu observed=%llu delta=%lld "
            "(genesis=%llu minted=%llu burned=%llu utxo=%llu self_stake=%llu "
            "delegated=%llu pool=%llu)",
            (unsigned long long)expected,
            (unsigned long long)observed,
            (long long)((int64_t)observed - (int64_t)expected),
            (unsigned long long)sup.genesis_supply,
            (unsigned long long)sup.total_minted,
            (unsigned long long)sup.total_burned,
            (unsigned long long)utxo_native,
            (unsigned long long)self_stake_sum,
            (unsigned long long)total_delegated_sum,
            (unsigned long long)epoch_pool_sum);
        return -1;
    }
    return 0;

overflow_fail:
    QGP_LOG_ERROR(LOG_TAG,
        "SUPPLY INVARIANT: observed sum overflow (utxo=%llu self_stake=%llu "
        "delegated=%llu pool=%llu)",
        (unsigned long long)utxo_native,
        (unsigned long long)self_stake_sum,
        (unsigned long long)total_delegated_sum,
        (unsigned long long)epoch_pool_sum);
    return -1;
}

bool supply_invariant_violated(nodus_witness_t *w) {
    if (!w || !w->db) return false;

    bool violated = false;

    nodus_witness_supply_t sup;
    uint64_t utxo_total = 0;
    /* D1 review: `== 0` (row present) is the correct predicate under the
     * three-valued contract and is unchanged by it. This function is the
     * ADVISORY diagnostic; neither of its two callers can reject a block
     * on its verdict — finalize_block discards it outright
     * (`(void)supply_invariant_violated(w)`) and the attribution replay
     * only emits a per-TX log line on a path that is already returning
     * -1. So neither an absent row (1) nor a DB error (-1) may be
     * reported here as a violation. The HARD gate that DOES reject is
     * check_supply_invariant_v016 above. */
    if (nodus_witness_supply_get(w, &sup) == 0 &&
        nodus_witness_utxo_sum_by_token(w, NULL, &utxo_total) == 0) {

        /* Effective supply = genesis + cumulative inflation-mint at current
         * height. Locks (validator.self_stake, delegation.amount) and pools
         * (validator.accumulator, block_fee_pool) are NOT in utxo_total but
         * ARE in effective_supply — so effective_supply > utxo_total is the
         * healthy case. Violation = utxo_total > effective_supply (impossible
         * without a bug) OR the delta exceeds known locks+pools sum. The
         * latter requires aggregating validator/delegation tables — left as
         * a Phase 10+ TODO; for now this check is advisory. */
        uint64_t block_h  = nodus_witness_block_height(w);
        uint64_t minted   = nodus_emission_total_minted(block_h, 1ULL);
        uint64_t effective = sup.genesis_supply;
        /* Saturating add to guard against a pathological mint overflow. */
        if (minted > UINT64_MAX - effective) effective = UINT64_MAX;
        else effective += minted;

        if (utxo_total > effective) {
            QGP_LOG_ERROR(LOG_TAG,
                "SUPPLY INVARIANT VIOLATION (impossible): utxo_sum=%llu > "
                "effective=%llu (genesis=%llu minted=%llu height=%llu delta=%lld)",
                (unsigned long long)utxo_total,
                (unsigned long long)effective,
                (unsigned long long)sup.genesis_supply,
                (unsigned long long)minted,
                (unsigned long long)block_h,
                (long long)(utxo_total - effective));
            violated = true;
        } else if (sup.genesis_supply != utxo_total) {
            /* Advisory: delta should equal locks + pools. Full check TODO. */
            QGP_LOG_DEBUG(LOG_TAG,
                "supply: genesis=%llu minted=%llu effective=%llu utxo_sum=%llu "
                "locks+pools=%llu (height=%llu)",
                (unsigned long long)sup.genesis_supply,
                (unsigned long long)minted,
                (unsigned long long)effective,
                (unsigned long long)utxo_total,
                (unsigned long long)(effective - utxo_total),
                (unsigned long long)block_h);
        }
    }

    /* Per-token supply invariant: each custom token's UTXO sum must equal
     * its registered initial_supply (custom tokens have no fee burn). */
    nodus_witness_token_entry_t tokens[64];
    int token_count = 0;
    if (nodus_witness_token_list(w, tokens, 64, &token_count) == 0) {
        for (int ti = 0; ti < token_count; ti++) {
            uint64_t token_utxo_sum = 0;
            if (nodus_witness_utxo_sum_by_token(w, tokens[ti].token_id,
                                                  &token_utxo_sum) == 0) {
                if (tokens[ti].supply != token_utxo_sum) {
                    QGP_LOG_ERROR(LOG_TAG,
                        "TOKEN SUPPLY INVARIANT VIOLATION: "
                        "token=%s initial=%llu utxo_sum=%llu (delta=%lld)",
                        tokens[ti].symbol,
                        (unsigned long long)tokens[ti].supply,
                        (unsigned long long)token_utxo_sum,
                        (long long)(tokens[ti].supply - token_utxo_sum));
                    violated = true;
                }
            }
        }
    }

    return violated;
}

/* ── Phase 8: Stake & delegation state mutation helpers ───────────── */

/* Compute the offset in tx_data at which the type-specific appended
 * fields begin (i.e. the byte right after the last signer's signature),
 * and (optionally) return a pointer to signers[0].pubkey inside tx_data.
 *
 * Wire layout (design 2.3; see dnac/src/transaction/serialize.c):
 *   header(74) then input_count(1) then inputs then output_count(1) then outputs
 *   then witness_count(1) then witnesses then signer_count(1) then signers
 *   then type-specific appended fields
 *   then has_chain_def(1) then optional chain_def blob.
 *
 * Returns 0 on success, -1 on malformed / truncated input. signer_pk_out
 * may be NULL.
 */
static int compute_appended_fields_offset(const uint8_t *tx_data,
                                            uint32_t tx_len,
                                            size_t *off_out,
                                            const uint8_t **signer_pk_out) {
    if (!tx_data || !off_out) return -1;

    /* v2 header: version(1) + type(1) + timestamp(8) + tx_hash(64) + committed_fee(8) = 82 */
    if (tx_len < DNAC_TX_HEADER_SIZE) return -1;
    size_t off = DNAC_TX_HEADER_SIZE;

    /* Inputs */
    if (off >= tx_len) return -1;
    uint8_t input_count = tx_data[off++];
    const size_t input_size = NODUS_T3_NULLIFIER_LEN + 8 + 64;
    if ((size_t)input_count * input_size > tx_len - off) return -1;
    off += (size_t)input_count * input_size;

    /* Outputs (variable memo) */
    if (off >= tx_len) return -1;
    uint8_t output_count = tx_data[off++];
    for (int i = 0; i < output_count; i++) {
        if (off + 235 > tx_len) return -1;
        off += 1 + 129 + 8 + 64 + 32;   /* version + fp + amount + token_id + seed */
        uint8_t memo_len = tx_data[off++];
        if (memo_len > tx_len - off) return -1;
        off += memo_len;
    }

    /* Witnesses */
    if (off >= tx_len) return -1;
    uint8_t witness_count = tx_data[off++];
    const size_t witness_size = 32 + DNAC_SIGNATURE_SIZE + 8 + DNAC_PUBKEY_SIZE;
    if ((size_t)witness_count * witness_size > tx_len - off) return -1;
    off += (size_t)witness_count * witness_size;

    /* Signers */
    if (off >= tx_len) return -1;
    uint8_t signer_count = tx_data[off++];
    if (signer_count == 0) return -1;
    const size_t signer_size = DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE;
    if ((size_t)signer_count * signer_size > tx_len - off) return -1;

    if (signer_pk_out) {
        /* signers[0].pubkey sits at current offset (pubkey first, sig after). */
        *signer_pk_out = tx_data + off;
    }
    off += (size_t)signer_count * signer_size;

    *off_out = off;
    return 0;
}

/* Sum native-DNAC (token_id all-zero) input and output amounts. Needed
 * by DELEGATE for exact delegation_amount = in - out - fee. Returns 0
 * on success, -1 on malformed tx_data. */
static int sum_native_dnac_in_out(const uint8_t *tx_data,
                                    uint32_t tx_len,
                                    uint64_t *in_sum_out,
                                    uint64_t *out_sum_out) {
    static const uint8_t zero_tid[64] = {0};

    if (!tx_data || !in_sum_out || !out_sum_out) return -1;
    if (tx_len < DNAC_TX_HEADER_SIZE) return -1;

    uint64_t in_sum = 0;
    uint64_t out_sum = 0;

    size_t off = DNAC_TX_HEADER_SIZE;

    if (off >= tx_len) return -1;
    uint8_t input_count = tx_data[off++];
    for (int i = 0; i < input_count; i++) {
        if (off + NODUS_T3_NULLIFIER_LEN + 8 + 64 > tx_len) return -1;
        off += NODUS_T3_NULLIFIER_LEN;
        uint64_t amt;
        memcpy(&amt, tx_data + off, 8);
        off += 8;
        const uint8_t *tid = tx_data + off;
        off += 64;
        if (memcmp(tid, zero_tid, 64) == 0) {
            in_sum += amt;
        }
    }

    if (off >= tx_len) return -1;
    uint8_t output_count = tx_data[off++];
    for (int i = 0; i < output_count; i++) {
        if (off + 235 > tx_len) return -1;
        off += 1 + 129;
        uint64_t amt;
        memcpy(&amt, tx_data + off, 8);
        off += 8;
        const uint8_t *tid = tx_data + off;
        off += 64;
        off += 32;
        uint8_t memo_len = tx_data[off++];
        if (memo_len > tx_len - off) return -1;
        off += memo_len;
        if (memcmp(tid, zero_tid, 64) == 0) {
            out_sum += amt;
        }
    }

    *in_sum_out = in_sum;
    *out_sum_out = out_sum;
    return 0;
}

/* Phase 8 Task 41 — DELEGATE state mutation.
 *
 * Parses validator_pubkey[2592] appended field, fetches target validator
 * + current reward accumulator, inserts (or updates) delegation row with
 * reward_snapshot = V.accumulator, bumps V.total_delegated +
 * V.external_delegated.
 *
 * delegation_amount is computed as
 *     native_input_sum - native_output_sum - committed_fee
 * (DELEGATE consumes DNAC inputs >= amount + fee, outputs are change
 * only; see design 2.4).
 */
/* Non-static so test executables (compiled with NODUS_WITNESS_INTERNAL_API
 * via register_witness_test) can call directly — the apply_tx_to_state
 * precedent below. Declared ONLY in nodus_witness_bft_internal.h, never
 * in a production-facing header; production callers reach it through
 * apply_tx_to_state's NODUS_W_TX_DELEGATE branch. Exported for the
 * per-validator delegator-cap regression (O15J Block 2), which needs to
 * drive this rule without standing up the UTXO/nullifier machinery that
 * only affects the committed_fee this function is HANDED. */
int apply_delegate(nodus_witness_t *w,
                    const uint8_t *tx_data, uint32_t tx_len,
                    uint64_t block_height,
                    uint64_t committed_fee) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_delegate: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    /* v0.17.1 DELEGATE type-specific fields: validator_pubkey(2592) || delegation_amount(u64 BE). */
    if (off + DNAC_PUBKEY_SIZE + 8 > tx_len) {
        fprintf(stderr, "%s: apply_delegate: truncated appended fields (need %zu, have %u)\n",
                LOG_TAG, off + DNAC_PUBKEY_SIZE + 8, tx_len);
        return -1;
    }
    const uint8_t *validator_pubkey = tx_data + off;

    /* Rule S defense-in-depth: reject self-delegation. */
    if (memcmp(signer_pubkey, validator_pubkey, DNAC_PUBKEY_SIZE) == 0) {
        fprintf(stderr, "%s: apply_delegate: self-delegation rejected (Rule S)\n",
                LOG_TAG);
        return -1;
    }

    /* Read explicit delegation_amount from wire (v0.17.1: no more implicit
     * input−output inference; SB-1 debt closed). The canonical consistency
     * rule Σ(native_in) == Σ(native_out) + committed_fee + delegation_amount
     * is enforced below with safe_add to rule out unsigned-wrap attacks
     * (SEC-01). */
    const uint8_t *delegation_amount_be = tx_data + off + DNAC_PUBKEY_SIZE;
    uint64_t delegation_amount = 0;
    for (int i = 0; i < 8; i++) {
        delegation_amount = (delegation_amount << 8) | (uint64_t)delegation_amount_be[i];
    }

    /* SEC-01 bounds: delegation_amount must be non-zero and within supply. */
    if (delegation_amount == 0) {
        fprintf(stderr, "%s: apply_delegate: zero delegation_amount rejected\n",
                LOG_TAG);
        return -1;
    }
    if (delegation_amount > DNAC_DEFAULT_TOTAL_SUPPLY) {
        fprintf(stderr, "%s: apply_delegate: delegation_amount (%llu) exceeds total supply\n",
                LOG_TAG, (unsigned long long)delegation_amount);
        return -1;
    }

    /* Addition-only consistency check (SEC-01): reject any TX where the
     * native flow does not balance against the declared fee + state amount.
     * Overflow in the RHS accumulation is itself a reject signal. */
    uint64_t input_sum = 0, output_sum = 0;
    if (sum_native_dnac_in_out(tx_data, tx_len, &input_sum, &output_sum) != 0) {
        fprintf(stderr, "%s: apply_delegate: sum_native_dnac_in_out failed\n",
                LOG_TAG);
        return -1;
    }
    uint64_t expected_in = 0;
    if (safe_add_u64(output_sum, committed_fee, &expected_in) != 0 ||
        safe_add_u64(expected_in, delegation_amount, &expected_in) != 0) {
        fprintf(stderr, "%s: apply_delegate: RHS overflow (out=%llu fee=%llu delegation=%llu)\n",
                LOG_TAG,
                (unsigned long long)output_sum,
                (unsigned long long)committed_fee,
                (unsigned long long)delegation_amount);
        return -1;
    }
    if (input_sum != expected_in) {
        fprintf(stderr,
                "%s: apply_delegate: consistency violation "
                "(in=%llu != out=%llu + fee=%llu + delegation=%llu)\n",
                LOG_TAG,
                (unsigned long long)input_sum,
                (unsigned long long)output_sum,
                (unsigned long long)committed_fee,
                (unsigned long long)delegation_amount);
        return -1;
    }

    /* Fetch target validator. */
    dnac_validator_record_t v;
    int rc = nodus_validator_get(w, validator_pubkey, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_delegate: validator not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }
    /* S3: delegation targets any BONDED validator. ELIGIBLE means "bonded
     * but not seated this epoch" — refusing it would make a validator that
     * lost its seat undelegatable, and since ranking is what wins a seat
     * back, that would be a one-way ratchet out of the active set.
     * RETIRING / UNSTAKED / AUTO_RETIRED stay rejected (exit states). */
    if (v.status != DNAC_VALIDATOR_ACTIVE &&
        v.status != DNAC_VALIDATOR_ELIGIBLE) {
        fprintf(stderr, "%s: apply_delegate: validator not bonded "
                "(status=%u)\n", LOG_TAG, v.status);
        return -1;
    }

    /* v0.16: reward accumulator snapshot removed — distribution is now
     * push-per-epoch via apply_epoch_settlement (Stage E). Delegations
     * applied mid-epoch become eligible at the NEXT epoch snapshot. */

    /* O15J Block 2 — per-validator delegator cap, enforced HERE at
     * admission rather than papered over at snapshot time.
     *
     * The epoch snapshot serializes at most
     * NODUS_MAX_DELEGATORS_PER_VALIDATOR delegators per committee member
     * (nodus_witness_epoch.c NODUS_EPOCH_MAX_DELEGS_PER_VAL, now an alias
     * of that same constant) while writing the validator's FULL
     * total_delegated. Without this gate a validator could hold more
     * delegators than the blob can carry, and every delegator past the
     * cap would be unpaid forever with its share burned. Bounding the ROW
     * COUNT is what makes that impossible — the snapshot can never be
     * ASKED to truncate.
     *
     * VERDICT, not a node fault: the count is a deterministic function of
     * committed state, so every honest node counts the same rows and
     * reaches the same answer. It joins the Rule S / not-bonded rejects
     * above in this function's single -1 class — the same shape
     * apply_unstake already uses for its Rule A count check below.
     *
     * FAIL-CLOSED: an unreadable count REJECTS. It is never read as
     * "zero, therefore admit" — that would turn a local DB fault into an
     * admission every honest peer refuses.
     *
     * A TOP-UP is still admitted at the cap: an existing (delegator,
     * validator) row adds no NEW delegator, so the count does not move
     * and the snapshot still holds everyone. Only a delegator that does
     * not have a row yet is gated.
     *
     * JUDGMENT: nodus_delegation_get returns 1 for absent and -1 for a
     * read error, and both are treated here as "not an existing
     * delegator" ⇒ reject. At the cap boundary that is the fail-closed
     * direction for either cause, so the conflation can never admit. */
    int deleg_count = 0;
    if (nodus_delegation_count_by_validator(w, validator_pubkey,
                                             &deleg_count) != 0) {
        fprintf(stderr, "%s: apply_delegate: count_by_validator failed — "
                "delegator cap cannot be evaluated, rejecting\n", LOG_TAG);
        return -1;
    }
    if (deleg_count >= NODUS_MAX_DELEGATORS_PER_VALIDATOR) {
        dnac_delegation_record_t existing_probe;
        if (nodus_delegation_get(w, signer_pubkey, validator_pubkey,
                                  &existing_probe) != 0) {
            fprintf(stderr, "%s: apply_delegate: validator already has %d "
                    "delegators (cap %d) and this delegator is not one of "
                    "them — rejected\n", LOG_TAG, deleg_count,
                    NODUS_MAX_DELEGATORS_PER_VALIDATOR);
            return -1;
        }
        /* an existing delegator topping up: the row count does not move */
    }

    /* Insert (or update if already exists) delegation row. */
    dnac_delegation_record_t d;
    memset(&d, 0, sizeof(d));
    memcpy(d.delegator_pubkey, signer_pubkey, DNAC_PUBKEY_SIZE);
    memcpy(d.validator_pubkey, validator_pubkey, DNAC_PUBKEY_SIZE);
    d.amount             = delegation_amount;
    d.delegated_at_block = block_height;

    int rc2 = nodus_delegation_insert(w, &d);
    if (rc2 == -2) {
        /* Existing row — top up amount + refresh Rule O block.
         * Note: Rule O's "1 epoch min hold" is measured from the most
         * recent delegated_at_block, so resetting here imposes a fresh
         * hold period on the added amount. */
        dnac_delegation_record_t existing;
        int gr = nodus_delegation_get(w, signer_pubkey, validator_pubkey,
                                       &existing);
        if (gr != 0) {
            fprintf(stderr, "%s: apply_delegate: PK collision but get failed (rc=%d)\n",
                    LOG_TAG, gr);
            return -1;
        }
        /* Overflow guard */
        if (existing.amount > UINT64_MAX - delegation_amount) {
            fprintf(stderr, "%s: apply_delegate: amount overflow\n", LOG_TAG);
            return -1;
        }
        existing.amount += delegation_amount;
        existing.delegated_at_block = block_height;
        rc2 = nodus_delegation_update(w, &existing);
    }
    rc = rc2;
    if (rc != 0) {
        fprintf(stderr, "%s: apply_delegate: delegation insert/update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    /* Bump validator totals. Rule S blocks self-delegation so every
     * delegation is external. */
    if (v.total_delegated > UINT64_MAX - delegation_amount ||
        v.external_delegated > UINT64_MAX - delegation_amount) {
        fprintf(stderr, "%s: apply_delegate: validator totals overflow\n", LOG_TAG);
        return -1;
    }
    v.total_delegated    += delegation_amount;
    v.external_delegated += delegation_amount;
    rc = nodus_validator_update(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_delegate: validator_update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    return 0;
}

/* Phase 8 Task 40 — STAKE state mutation.
 *
 * Parses the type-specific appended fields (commission_bps +
 * unstake_destination_fp + purpose_tag), inserts a new validator row
 * with self_stake=10M, bumps validator_stats.active_count.
 * (v0.16: reward row seeding removed — push-settlement model has no
 * per-validator reward state.)
 */
static int apply_stake(nodus_witness_t *w,
                        const uint8_t *tx_data, uint32_t tx_len,
                        uint64_t block_height,
                        uint64_t committed_fee) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_stake: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    if (off + 2 + 64 + DNAC_STAKE_PURPOSE_TAG_LEN > tx_len) {
        fprintf(stderr, "%s: apply_stake: truncated appended fields\n", LOG_TAG);
        return -1;
    }

    uint16_t commission_bps = ((uint16_t)tx_data[off] << 8) |
                               (uint16_t)tx_data[off + 1];
    const uint8_t *unstake_fp_raw = tx_data + off + 2;
    /* purpose_tag bytes are validated by Phase 7 STAKE verify; we trust
     * them here. */

    /* ── S3 (owner decision O-3): the bond is what the TX actually locked.
     *
     * Before S3 this was hardcoded to DNAC_SELF_STAKE_AMOUNT while the TX
     * could legally carry more inputs than that; the surplus vanished from
     * the ledger's point of view. The bond is now derived exactly as
     * DELEGATE derives delegation_amount (see apply_delegate above):
     *
     *     bond = Σnative_in − Σnative_out − committed_fee
     *
     * with bond >= DNAC_SELF_STAKE_AMOUNT REQUIRED. That minimum is the DNA
     * self-bond floor and can only be met by the staker's own inputs;
     * delegation can never contribute any part of it — a delegation is a
     * different TX type (DNAC_TX_DELEGATE) writing a different table
     * (delegations), and it lands in external_delegated, never in
     * self_stake.
     *
     * LIVE BEHAVIOUR IS UNCHANGED: the shipped client builds STAKE with
     * inputs == DNAC_SELF_STAKE_AMOUNT + fee and change outputs covering
     * the remainder (dnac/src/transaction/transaction.c
     * dnac_tx_create_stake), so every existing TX yields
     * bond == DNAC_SELF_STAKE_AMOUNT exactly. */
    uint64_t input_sum = 0, output_sum = 0;
    if (sum_native_dnac_in_out(tx_data, tx_len, &input_sum, &output_sum) != 0) {
        fprintf(stderr, "%s: apply_stake: sum_native_dnac_in_out failed\n",
                LOG_TAG);
        return -1;
    }
    uint64_t spent = 0;
    if (safe_add_u64(output_sum, committed_fee, &spent) != 0 ||
        spent > input_sum) {
        fprintf(stderr,
                "%s: apply_stake: native flow does not balance "
                "(in=%llu out=%llu fee=%llu)\n", LOG_TAG,
                (unsigned long long)input_sum,
                (unsigned long long)output_sum,
                (unsigned long long)committed_fee);
        return -1;
    }
    uint64_t bond = input_sum - spent;
    if (bond < DNAC_SELF_STAKE_AMOUNT) {
        fprintf(stderr,
                "%s: apply_stake: bond %llu < minimum self-bond %llu\n",
                LOG_TAG, (unsigned long long)bond,
                (unsigned long long)DNAC_SELF_STAKE_AMOUNT);
        return -1;
    }

    dnac_validator_record_t v;
    memset(&v, 0, sizeof(v));
    memcpy(v.pubkey, signer_pubkey, DNAC_PUBKEY_SIZE);
    v.self_stake              = bond;
    v.total_delegated         = 0;
    v.external_delegated      = 0;
    v.commission_bps          = commission_bps;
    v.pending_commission_bps  = 0;
    v.pending_effective_block = 0;
    v.status                  = DNAC_VALIDATOR_ACTIVE;
    v.active_since_block      = block_height;
    v.unstake_commit_block    = 0;
    v.last_validator_update_block = 0;
    v.consecutive_missed_epochs   = 0;
    v.last_signed_block           = 0;

    /* Convert 64 raw bytes to 128-char hex + NUL for the TEXT schema. */
    qgp_fp_raw_to_hex(unstake_fp_raw, (char *)v.unstake_destination_fp);

    /* If the destination fingerprint derives from the signer's own
     * pubkey, populate unstake_destination_pubkey immediately so the
     * post-cooldown SPEND can verify. Otherwise leave zero. */
    uint8_t signer_fp_raw[64];
    qgp_sha3_512(signer_pubkey, DNAC_PUBKEY_SIZE, signer_fp_raw);
    if (memcmp(signer_fp_raw, unstake_fp_raw, 64) == 0) {
        memcpy(v.unstake_destination_pubkey, signer_pubkey, DNAC_PUBKEY_SIZE);
    }

    int rc = nodus_validator_insert(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_stake: validator_insert failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    char *err = NULL;
    int src = sqlite3_exec(w->db,
        "UPDATE validator_stats SET value = value + 1 WHERE key = 'active_count'",
        NULL, NULL, &err);
    if (src != SQLITE_OK) {
        fprintf(stderr, "%s: apply_stake: active_count bump failed: %s\n",
                LOG_TAG, err ? err : "(null)");
        if (err) sqlite3_free(err);
        return -1;
    }

    return 0;
}

/* Phase 8 Task 42 — UNSTAKE state mutation (phase 1 — RETIRING transition).
 *
 * UNSTAKE has no type-specific appended fields. The signer[0] pubkey is
 * the validator requesting retirement. On success:
 *   - status := RETIRING
 *   - unstake_commit_block := block_height
 *
 * Rule A defense-in-depth: require NO delegation records exist with
 * validator == signer[0]. Matches Phase 7 UNSTAKE verify rule A; this
 * is the last-line-of-defense check.
 *
 * Graduation to UNSTAKED + cooldown UTXO emission is deferred to phase
 * 2 (next epoch boundary). Keeps BFT peer set stable mid-epoch.
 */
static int apply_unstake(nodus_witness_t *w,
                          const uint8_t *tx_data, uint32_t tx_len,
                          uint64_t block_height) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_unstake: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    /* UNSTAKE has no appended fields — not enforced here (Phase 7
     * UNSTAKE verify is the source of truth for wire-level constraints). */

    /* Fetch validator — must exist and be ACTIVE. */
    dnac_validator_record_t v;
    int rc = nodus_validator_get(w, signer_pubkey, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_unstake: validator not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }
    /* S3: a BONDED validator may unstake whether or not it holds a seat
     * this epoch. Locking ELIGIBLE validators out of the exit path would
     * strand their bond until they happened to be re-selected. */
    if (v.status != DNAC_VALIDATOR_ACTIVE &&
        v.status != DNAC_VALIDATOR_ELIGIBLE) {
        fprintf(stderr, "%s: apply_unstake: validator not bonded "
                "(status=%u)\n", LOG_TAG, v.status);
        return -1;
    }

    /* Rule A defense-in-depth: reject if any delegator references this
     * validator. */
    int deleg_count = 0;
    if (nodus_delegation_count_by_validator(w, signer_pubkey,
                                              &deleg_count) != 0) {
        fprintf(stderr, "%s: apply_unstake: count_by_validator failed\n",
                LOG_TAG);
        return -1;
    }
    if (deleg_count != 0) {
        fprintf(stderr, "%s: apply_unstake: %d delegations still reference this validator (Rule A)\n",
                LOG_TAG, deleg_count);
        return -1;
    }

    v.status               = DNAC_VALIDATOR_RETIRING;
    v.unstake_commit_block = block_height;

    rc = nodus_validator_update(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_unstake: validator_update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    return 0;
}

/* Emit a synthetic native-DNAC UTXO owned by `owner_pubkey`. Used by
 * UNDELEGATE which produces payouts that are NOT encoded as wire-format
 * outputs in tx_data (update_utxo_set doesn't see them).
 *
 * The nullifier is derived deterministically as
 *   SHA3-512(tx_hash || kind_byte || u32_be(output_index))
 * where kind_byte disambiguates multiple synthetic UTXOs from the same
 * TX (e.g. UNDELEGATE emits 0x01 = principal and 0x02 = pending-reward).
 *
 * `output_index` MUST NOT collide with any wire-format output index used
 * by update_utxo_set. Callers pass a high base (e.g. 100+) to stay
 * clear of wire outputs which start at 0.
 *
 * Returns 0 on success, -1 on error. `unlock_block = 0` ⇒ immediately
 * spendable.
 */
static int emit_synthetic_utxo(nodus_witness_t *w,
                                 const uint8_t *tx_hash,
                                 const uint8_t *owner_pubkey,
                                 uint64_t amount,
                                 uint64_t block_height,
                                 uint8_t kind_byte,
                                 uint32_t output_index,
                                 uint64_t unlock_block) {
    /* Derive synthetic nullifier: SHA3-512(tx_hash || kind || index_be). */
    uint8_t preimage[64 + 1 + 4];
    memcpy(preimage, tx_hash, 64);
    preimage[64] = kind_byte;
    preimage[65] = (uint8_t)((output_index >> 24) & 0xff);
    preimage[66] = (uint8_t)((output_index >> 16) & 0xff);
    preimage[67] = (uint8_t)((output_index >> 8) & 0xff);
    preimage[68] = (uint8_t)(output_index & 0xff);
    uint8_t nullifier[64];
    qgp_sha3_512(preimage, sizeof(preimage), nullifier);

    /* Owner fingerprint = hex-encoded SHA3-512(owner_pubkey). */
    uint8_t owner_fp_raw[QGP_FP_RAW_BYTES];
    qgp_sha3_512(owner_pubkey, DNAC_PUBKEY_SIZE, owner_fp_raw);
    char owner_fp_hex[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(owner_fp_raw, owner_fp_hex);

    /* Native DNAC token_id = 64 zeros. */
    uint8_t zero_token_id[64];
    memset(zero_token_id, 0, sizeof(zero_token_id));

    int rc = nodus_witness_utxo_add_locked(w, nullifier, owner_fp_hex,
                                             amount, tx_hash, output_index,
                                             block_height, zero_token_id,
                                             unlock_block);
    if (rc != 0) {
        fprintf(stderr, "%s: emit_synthetic_utxo: utxo_add_locked failed (rc=%d, kind=0x%02x, idx=%u)\n",
                LOG_TAG, rc, kind_byte, output_index);
        return -1;
    }
    return 0;
}

/* Phase 8 Task 46 — Emit a synthetic UTXO directly owned by a precomputed
 * hex fingerprint. Used by the epoch-boundary graduation path where the
 * owner is a stored `unstake_destination_fp` (validator record field) and
 * the validator's own pubkey is not the owner. Mirrors emit_synthetic_utxo
 * except it skips the SHA3-512(pubkey) fp derivation step.
 *
 * owner_fp_hex MUST be the 128-char lowercase hex fingerprint + NUL. The
 * nullifier derivation, token_id (zeros), and locked-UTXO insert path are
 * identical to emit_synthetic_utxo so the two helpers share identical
 * supply-accounting behavior.
 */
static int emit_synthetic_utxo_for_fp(nodus_witness_t *w,
                                         const uint8_t *tx_hash,
                                         const char *owner_fp_hex,
                                         uint64_t amount,
                                         uint64_t block_height,
                                         uint8_t kind_byte,
                                         uint32_t output_index,
                                         uint64_t unlock_block) {
    /* Same nullifier derivation as emit_synthetic_utxo. */
    uint8_t preimage[64 + 1 + 4];
    memcpy(preimage, tx_hash, 64);
    preimage[64] = kind_byte;
    preimage[65] = (uint8_t)((output_index >> 24) & 0xff);
    preimage[66] = (uint8_t)((output_index >> 16) & 0xff);
    preimage[67] = (uint8_t)((output_index >> 8) & 0xff);
    preimage[68] = (uint8_t)(output_index & 0xff);
    uint8_t nullifier[64];
    qgp_sha3_512(preimage, sizeof(preimage), nullifier);

    uint8_t zero_token_id[64];
    memset(zero_token_id, 0, sizeof(zero_token_id));

    int rc = nodus_witness_utxo_add_locked(w, nullifier, owner_fp_hex,
                                             amount, tx_hash, output_index,
                                             block_height, zero_token_id,
                                             unlock_block);
    if (rc != 0) {
        fprintf(stderr, "%s: emit_synthetic_utxo_for_fp: utxo_add_locked failed (rc=%d, kind=0x%02x, idx=%u)\n",
                LOG_TAG, rc, kind_byte, output_index);
        return -1;
    }
    return 0;
}

/* Phase 8 Task 43 — UNDELEGATE state mutation.
 *
 * Parses validator_pubkey[2592] + amount[8 BE] appended fields. Computes
 * pending reward from the u128 accumulator math (design §3.5):
 *     diff       = V.accumulator − D.reward_snapshot              (u128 BE)
 *     pending_w  = (diff × D.amount) >> 64                        (u128)
 *     pending    = (uint64) pending_w.lo                          (design §3.5: shift 64)
 *
 * Emits TWO synthetic UTXOs (Rule Q — always both, even if pending==0
 * to preserve supply accounting invariants):
 *   kind 0x01 = principal UTXO (amount = undelegate_amount)
 *   kind 0x02 = pending-reward UTXO (amount = pending)
 *
 * Advances D.reward_snapshot := V.accumulator. If the delegation is
 * fully drained (undelegate_amount == D.amount), deletes the row;
 * otherwise decrements D.amount. Decrements V.total_delegated and
 * V.external_delegated (Rule S — all delegations are external).
 *
 * No validator status gate: UNDELEGATE is permitted against any status
 * so delegators of an AUTO_RETIRED / RETIRING / UNSTAKED validator can
 * always pull their principal. Rule B only restricts new DELEGATEs.
 */
static int apply_undelegate(nodus_witness_t *w,
                             const uint8_t *tx_data, uint32_t tx_len,
                             uint64_t block_height,
                             const uint8_t *tx_hash) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_undelegate: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    /* Appended: validator_pubkey[2592] + amount[8 BE] = 2600 bytes. */
    if (off + DNAC_PUBKEY_SIZE + 8 > tx_len) {
        fprintf(stderr, "%s: apply_undelegate: truncated appended fields\n", LOG_TAG);
        return -1;
    }
    const uint8_t *validator_pubkey = tx_data + off;
    uint64_t undelegate_amount = 0;
    for (int i = 0; i < 8; i++) {
        undelegate_amount = (undelegate_amount << 8) |
                             (uint64_t)tx_data[off + DNAC_PUBKEY_SIZE + i];
    }

    /* Fetch delegation. */
    dnac_delegation_record_t d;
    int rc = nodus_delegation_get(w, signer_pubkey, validator_pubkey, &d);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_undelegate: delegation not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }
    if (undelegate_amount == 0 || undelegate_amount > d.amount) {
        fprintf(stderr, "%s: apply_undelegate: invalid amount (req=%llu, have=%llu)\n",
                LOG_TAG,
                (unsigned long long)undelegate_amount,
                (unsigned long long)d.amount);
        return -1;
    }

    /* Fetch validator. */
    dnac_validator_record_t v;
    rc = nodus_validator_get(w, validator_pubkey, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_undelegate: validator not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    /* v0.16: reward auto-claim removed — push-settlement distributes
     * accrued rewards at each epoch boundary regardless of UNDELEGATE
     * timing. UNDELEGATE only returns the principal. */

    /* Emit principal UTXO (kind 0x01) — always spendable immediately. */
    if (emit_synthetic_utxo(w, tx_hash, signer_pubkey, undelegate_amount,
                              block_height, /*kind=*/0x01,
                              /*output_index=*/100, /*unlock=*/0) != 0) {
        return -1;
    }

    if (undelegate_amount == d.amount) {
        /* Fully drained — remove the row. */
        rc = nodus_delegation_delete(w, signer_pubkey, validator_pubkey);
    } else {
        d.amount -= undelegate_amount;
        rc = nodus_delegation_update(w, &d);
    }
    if (rc != 0) {
        fprintf(stderr, "%s: apply_undelegate: delegation update/delete failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    /* Decrement validator totals. Rule S ⇒ all delegations are external. */
    if (v.total_delegated < undelegate_amount ||
        v.external_delegated < undelegate_amount) {
        fprintf(stderr, "%s: apply_undelegate: validator total underflow\n", LOG_TAG);
        return -1;
    }
    v.total_delegated    -= undelegate_amount;
    v.external_delegated -= undelegate_amount;
    rc = nodus_validator_update(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_undelegate: validator_update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    return 0;
}

/* Phase 8 Task 45 — VALIDATOR_UPDATE state mutation.
 *
 * Appended fields (design §2.3):
 *   new_commission_bps[2 BE] || signed_at_block[8 BE]  (10 bytes total)
 *
 * Commission-change semantics (design §3.9):
 *   - Increase (new > current): defer — set pending_commission_bps +
 *     pending_effective_block := max(next_epoch_boundary, current_block +
 *     DNAC_EPOCH_LENGTH). Delegators get a full epoch of notice.
 *   - Decrease (new <= current): immediate — current_commission_bps :=
 *     new, pending fields cleared. Decreases are always delegator-safe,
 *     no notice needed.
 *   - Equal (new == current): falls through the decrease branch; the
 *     net effect is clearing any stale pending entry without mutating
 *     current. Benign.
 *
 * Always: v.last_validator_update_block := block_height (Rule K cooldown).
 *
 * Requires the validator row to exist with status ∈ {ACTIVE, RETIRING}.
 * UNSTAKED / AUTO_RETIRED validators cannot update commissions — their
 * stake is frozen.
 *
 * signed_at_block is a verify-time field (freshness); not consumed here.
 */
static int apply_validator_update(nodus_witness_t *w,
                                     const uint8_t *tx_data, uint32_t tx_len,
                                     uint64_t block_height) {
    size_t off = 0;
    const uint8_t *signer_pubkey = NULL;
    if (compute_appended_fields_offset(tx_data, tx_len, &off, &signer_pubkey) != 0) {
        fprintf(stderr, "%s: apply_validator_update: malformed tx_data\n", LOG_TAG);
        return -1;
    }

    /* Appended: new_commission_bps[2 BE] + signed_at_block[8 BE]. */
    if (off + 2 + 8 > tx_len) {
        fprintf(stderr, "%s: apply_validator_update: truncated appended fields\n", LOG_TAG);
        return -1;
    }
    uint16_t new_bps = ((uint16_t)tx_data[off] << 8) |
                        (uint16_t)tx_data[off + 1];
    /* signed_at_block at off+2..off+9 — verify-time, ignored here. */

    if (new_bps > DNAC_COMMISSION_BPS_MAX) {
        fprintf(stderr, "%s: apply_validator_update: new_bps %u > max %u\n",
                LOG_TAG, new_bps, DNAC_COMMISSION_BPS_MAX);
        return -1;
    }

    dnac_validator_record_t v;
    int rc = nodus_validator_get(w, signer_pubkey, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_validator_update: validator not found (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }
    /* S3: ELIGIBLE joins the updatable set — it is a bonded state, and
     * commission is exactly what a validator tunes while trying to win a
     * seat back. RETIRING was already allowed (it keeps paying delegators
     * through its cooldown); UNSTAKED / AUTO_RETIRED stay rejected. */
    if (v.status != DNAC_VALIDATOR_ACTIVE &&
        v.status != DNAC_VALIDATOR_ELIGIBLE &&
        v.status != DNAC_VALIDATOR_RETIRING) {
        fprintf(stderr, "%s: apply_validator_update: validator status=%u not updatable\n",
                LOG_TAG, v.status);
        return -1;
    }

    if (new_bps > v.commission_bps) {
        /* Increase — defer one full epoch. */
        v.pending_commission_bps  = new_bps;
        uint64_t next_epoch_boundary =
            ((block_height / DNAC_EPOCH_LENGTH) + 1) * DNAC_EPOCH_LENGTH;
        uint64_t plus_epoch = block_height + DNAC_EPOCH_LENGTH;
        v.pending_effective_block = (next_epoch_boundary > plus_epoch)
                                     ? next_epoch_boundary
                                     : plus_epoch;
    } else {
        /* Decrease (or equal) — immediate + clear pending. */
        v.commission_bps          = new_bps;
        v.pending_commission_bps  = 0;
        v.pending_effective_block = 0;
    }
    v.last_validator_update_block = block_height;

    rc = nodus_validator_update(w, &v);
    if (rc != 0) {
        fprintf(stderr, "%s: apply_validator_update: validator_update failed (rc=%d)\n",
                LOG_TAG, rc);
        return -1;
    }

    return 0;
}

/* apply_tx_to_state — Phase 3 / Task 3.1.
 *
 * Per-TX state mutation: extracts the per-TX body of the legacy
 * commit_block_inner. Does NOT touch state_root, supply check, or
 * block_add — those live in finalize_block (Task 3.2). Suitable for
 * use inside both single-TX paths (caller invokes finalize_block once
 * after a single apply_tx_to_state) and multi-TX batch paths (caller
 * invokes apply_tx_to_state N times, then finalize_block once).
 *
 * The block_height parameter is the height at which the TX is being
 * committed — for single-TX paths it equals
 * nodus_witness_block_height(w) + 1; for batch paths all N TXs share
 * the same height (the height of the block they are being applied to).
 *
 * batch_ctx is a forward declaration for Phase 4's intra-batch
 * chained-UTXO defense. NULL is legal — the chained check is skipped,
 * which is what single-TX paths and the SAVEPOINT attribution replay
 * (Task 6.2) want.
 */
/* Non-static so test executables (compiled with NODUS_WITNESS_INTERNAL_API
 * via register_witness_test) can call directly. The function is not
 * declared in any public header — production callers reach it via
 * nodus_witness_commit_block / Phase 6 wrappers. */
int apply_tx_to_state(nodus_witness_t *w,
                       const uint8_t *tx_hash,
                       uint8_t tx_type,
                       const uint8_t *const *nullifiers,
                       uint8_t nullifier_count,
                       const uint8_t *tx_data,
                       uint32_t tx_len,
                       uint64_t block_height,
                       uint64_t block_timestamp,
                       nodus_witness_batch_ctx_t *batch_ctx,
                       const uint8_t *client_pubkey,
                       const uint8_t *client_sig) {
    bool failed = false;

    /* Phase 4 / Task 4.3 — layer-3 chained UTXO check.
     *
     * BEFORE consuming the input nullifiers, verify that none of them
     * appears in batch_ctx->seen_nullifiers (the future-nullifiers of
     * outputs produced by earlier TXs in this batch). NULL batch_ctx
     * skips the check — single-TX paths and the SAVEPOINT attribution
     * replay (Task 6.2) want that.
     *
     * Layer 2 (propose_batch) catches the same pattern at proposal
     * time, but layer 3 is the last line of defense — bug, attack, or
     * test hook bypass. The check happens BEFORE the nullifier_add
     * inserts so a violation rolls back via the outer transaction
     * without polluting state. */
    if (batch_ctx) {
        for (int j = 0; j < nullifier_count; j++) {
            for (int k = 0; k < batch_ctx->seen_count; k++) {
                if (memcmp(batch_ctx->seen_nullifiers[k], nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN) == 0) {
                    QGP_LOG_ERROR(LOG_TAG,
                        "layer-3: chained UTXO detected — input nullifier "
                        "matches an earlier TX's output future-nullifier");
                    return -1;
                }
            }
        }
    }

    /* Genesis-specific DB init (genesis_set + supply_init) moved to
     * commit_genesis — the only caller with tx_type==NODUS_W_TX_GENESIS.
     * commit_genesis has cd_supply from the chain_def trailer, which is
     * the correct initial_supply_raw. Deriving supply from output amounts
     * here missed the validator self-stake locks seeded by
     * genesis_seed_validators and tripped the supply invariant by exactly
     * stake_locked on every block. Restores this function's stated role
     * as pure per-TX state mutation (see function doc at top). */
    if (tx_type != NODUS_W_TX_GENESIS) {
        for (int i = 0; i < nullifier_count; i++) {
            int rc = nodus_witness_nullifier_add(w, nullifiers[i], tx_hash);
            if (rc != 0 && rc != -2) {
                fprintf(stderr, "%s: nullifier add %d failed\n", LOG_TAG, i);
                failed = true;
                break;
            }
        }
    }

    uint64_t committed_fee = 0;
    if (!failed && tx_data && tx_len > 0) {
        if (update_utxo_set(w, tx_hash, tx_type, nullifiers, nullifier_count,
                               tx_data, tx_len, &committed_fee) != 0) {
            fprintf(stderr, "%s: UTXO set update failed\n", LOG_TAG);
            failed = true;
        }
    }

    /* Phase 8 — stake & delegation state mutation. Runs AFTER
     * update_utxo_set so committed_fee is known (needed by DELEGATE for
     * exact amount calculation). Each helper is additive on top of the
     * nullifier/UTXO updates handled above: STAKE/DELEGATE/UNSTAKE all
     * still have at least one fee input whose nullifier was added. */
    if (!failed && tx_data && tx_len > 0) {
        if (tx_type == NODUS_W_TX_STAKE) {
            /* S3: committed_fee is now an INPUT to STAKE too — the bond is
             * Σnative_in − Σnative_out − committed_fee, the same identity
             * DELEGATE already used. */
            if (apply_stake(w, tx_data, tx_len, block_height,
                             committed_fee) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_DELEGATE) {
            if (apply_delegate(w, tx_data, tx_len, block_height,
                                committed_fee) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_UNSTAKE) {
            if (apply_unstake(w, tx_data, tx_len, block_height) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_UNDELEGATE) {
            if (apply_undelegate(w, tx_data, tx_len, block_height,
                                  tx_hash) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_VALIDATOR_UPDATE) {
            if (apply_validator_update(w, tx_data, tx_len,
                                         block_height) != 0) {
                failed = true;
            }
        } else if (tx_type == NODUS_W_TX_CHAIN_CONFIG) {
            if (nodus_chain_config_apply(w, tx_data, tx_len,
                                          block_height,
                                          block_timestamp) != 0) {
                failed = true;
            }
        }
        /* O15J Faz 3 — the type-15/16 activation apply lanes are DELETED
         * with the ceremony. Both types are permanently inadmissible at
         * verify (nodus_witness_verify.c, right after the tx-hash check),
         * so no such transaction can reach this dispatch. */
    }

    /* Phase 6 / Task 31 — fees no longer decrement current_supply.
     *
     * Legacy behavior: fee → burn UTXO, supply_add_burned decremented
     * current_supply by fee (invariant: genesis_supply = utxo_sum +
     * total_burned). New behavior: fees accumulate in w->block_fee_pool
     * and Phase 9 Task 49 routes them back into the committee. The
     * supply invariant now reads: genesis_supply == utxo_sum +
     * block_fee_pool (in-flight, zeroed per block) + total_burned
     * (legacy column, untouched by SPEND fees). supply_invariant_violated
     * is advisory during Phase 3 so the pool temporarily showing up as
     * a non-zero delta is tolerated until Phase 9 lands. */
    (void)committed_fee;

    /* Phase 3 / Task 3.4: supply check moved to finalize_block —
     * runs once per block instead of N times per batch. */

    if (!failed && tx_data && tx_len > 0) {
        uint64_t bh = block_height;  /* Phase 3 / Task 3.1: explicit param */

        /* Extract sender_fp and per-output data from TX binary.
         * Wire format: header(74) → inputs(1+N*(64+8+64)) → outputs(1+...)
         *              → witnesses(1+N*7259) → sender(pk(2592)+sig(4627)) */
        char sender_fp[129] = {0};

        /* Temporary output storage for tx_outputs table */
        char    out_fps[NODUS_WITNESS_MAX_TX_OUTPUTS][129];
        uint64_t out_amts[NODUS_WITNESS_MAX_TX_OUTPUTS];
        uint8_t out_tids[NODUS_WITNESS_MAX_TX_OUTPUTS][64];
        int    out_total = 0;

        if (tx_len > DNAC_TX_HEADER_SIZE) {
            size_t off = DNAC_TX_HEADER_SIZE; /* v0.17.1: header = ver(1)+type(1)+ts(8)+tx_hash(64)+committed_fee(8) = 82 */
            uint8_t in_count = tx_data[off++];
            off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64); /* nullifier + amount + token_id */

            /* Parse outputs — store each separately */
            if (off < tx_len) {
                uint8_t out_count = tx_data[off++];
                for (int oi = 0; oi < out_count && off + 235 <= tx_len; oi++) {
                    off += 1;  /* version */
                    if (oi < NODUS_WITNESS_MAX_TX_OUTPUTS) {
                        memcpy(out_fps[oi], tx_data + off, 128);
                        out_fps[oi][128] = '\0';
                    }
                    off += 129; /* fingerprint */
                    uint64_t amt;
                    memcpy(&amt, tx_data + off, 8);
                    if (oi < NODUS_WITNESS_MAX_TX_OUTPUTS) {
                        out_amts[oi] = amt;
                    }
                    off += 8;   /* amount */
                    if (oi < NODUS_WITNESS_MAX_TX_OUTPUTS) {
                        memcpy(out_tids[oi], tx_data + off, 64);
                    }
                    off += 64;  /* token_id */
                    off += 32;  /* seed */
                    uint8_t ml = tx_data[off++]; /* memo_len */
                    off += ml;
                    if (oi < NODUS_WITNESS_MAX_TX_OUTPUTS)
                        out_total = oi + 1;
                }
            }

            /* Skip witness signatures to reach signer_count */
            if (off < tx_len) {
                uint8_t wit_count = tx_data[off++];
                off += (size_t)wit_count * (32 + 4627 + 8 + 2592);
            }

            /* Skip signer_count byte; pubkey of signer[0] follows.
             * Wire: ... signer_count(1) || signers[each = pubkey(2592)+sig(4627)]
             * Historical off-by-one: hashed signer_count+pubkey[0..2590] →
             * fake fp stored for every TX (chain <00eef674> on v0.17.5). */
            if (off < tx_len) {
                off++;  /* signer_count */
            }

            /* Sender pubkey (2592 bytes) → SHA3-512 → hex fingerprint */
            if (off + 2592 <= tx_len) {
                qgp_sha3_512_fingerprint(tx_data + off, 2592, sender_fp);
            }
        }

        nodus_witness_tx_store(w, tx_hash, tx_type, tx_data, tx_len, bh,
                               block_timestamp, sender_fp, committed_fee,
                               client_pubkey, client_sig);

        /* Insert each output into tx_outputs table (with token_id) */
        for (int oi = 0; oi < out_total; oi++) {
            nodus_witness_tx_output_add(w, tx_hash, (uint32_t)oi,
                                          out_fps[oi], out_amts[oi],
                                          out_tids[oi]);
        }

        /* ── TOKEN_CREATE: register token in tokens table ──────── */
        if (tx_type == NODUS_W_TX_TOKEN_CREATE && tx_len > DNAC_TX_HEADER_SIZE) {
            /* Re-parse to extract output[0]'s token_id, amount, and memo.
             * Memo format: "name:symbol:decimals" */
            size_t toff = DNAC_TX_HEADER_SIZE;
            uint8_t tc_in_count = tx_data[toff++];
            toff += (size_t)tc_in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);

            if (toff < tx_len) {
                uint8_t tc_out_count = tx_data[toff++];
                if (tc_out_count > 0 && toff + 235 <= tx_len) {
                    toff += 1;   /* version */
                    const char *creator_fp = (const char *)(tx_data + toff);
                    toff += 129; /* fingerprint */
                    uint64_t token_supply;
                    memcpy(&token_supply, tx_data + toff, 8);
                    toff += 8;   /* amount */
                    const uint8_t *new_token_id = tx_data + toff;
                    toff += 64;  /* token_id */
                    toff += 32;  /* seed */

                    if (toff < tx_len) {
                        uint8_t memo_len = tx_data[toff++];
                        if (memo_len > 0 && toff + memo_len <= tx_len) {
                            /* Parse "name:symbol:decimals" from memo */
                            char memo_buf[256];
                            size_t copy_len = memo_len < sizeof(memo_buf) - 1
                                              ? memo_len : sizeof(memo_buf) - 1;
                            memcpy(memo_buf, tx_data + toff, copy_len);
                            memo_buf[copy_len] = '\0';

                            char *first_colon = strchr(memo_buf, ':');
                            if (first_colon) {
                                *first_colon = '\0';
                                char *second_colon = strchr(first_colon + 1, ':');
                                if (second_colon) {
                                    *second_colon = '\0';
                                    const char *t_name = memo_buf;
                                    const char *t_symbol = first_colon + 1;
                                    uint8_t t_decimals = (uint8_t)atoi(second_colon + 1);

                                    /* Use creator_fp from output (null-terminated 128-char hex) */
                                    char cfp[129];
                                    memcpy(cfp, creator_fp, 128);
                                    cfp[128] = '\0';

                                    nodus_witness_token_add(w, new_token_id,
                                        t_name, t_symbol, t_decimals,
                                        token_supply, cfp, 0, bh);

                                    fprintf(stderr, "%s: TOKEN_CREATE registered: "
                                            "name=%s symbol=%s decimals=%u "
                                            "supply=%llu (block %llu)\n",
                                            LOG_TAG, t_name, t_symbol,
                                            (unsigned)t_decimals,
                                            (unsigned long long)token_supply,
                                            (unsigned long long)bh);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (failed) return -1;

    nodus_witness_ledger_add(w, tx_hash, tx_type, nullifier_count,
                              block_height, block_timestamp);

    /* Phase 3 / Task 3.2: state_root + cached_state_root invalidation +
     * block_add moved to finalize_block. The caller is expected to call
     * finalize_block() once after applying all TXs in the block. */
    return 0;
}

/* Phase 8 Task 46 — epoch-boundary state transitions.
 *
 * Runs once per block inside finalize_block AFTER all per-TX
 * apply_tx_to_state calls have finished, but BEFORE state_root is
 * recomputed. No-op on non-epoch-boundary blocks.
 *
 * The three time-driven transitions implemented here:
 *
 *   1. Pending commission activation — any validator row whose
 *      pending_effective_block == block_height and whose
 *      pending_commission_bps != 0 promotes the pending rate to
 *      current and clears both pending columns.
 *
 *   2. RETIRING → UNSTAKED graduation — any validator in RETIRING
 *      status emits:
 *        (a) a time-locked principal UTXO (amount = DNAC_SELF_STAKE_AMOUNT,
 *            unlock_block = block_height + DNAC_UNSTAKE_COOLDOWN_BLOCKS)
 *        (b) an immediately-spendable unclaimed-rewards UTXO
 *            (amount = reward_record.validator_unclaimed, possibly zero
 *             to preserve supply-accounting symmetry — Rule Q)
 *      both owned by validator.unstake_destination_fp. Reward record's
 *      validator_unclaimed is then zeroed, validator transitions to
 *      UNSTAKED, and validator_stats.active_count is decremented.
 *
 *   3. Liveness-based AUTO_RETIRED — deferred. See TODO below.
 *
 * Committee election for the next epoch is ALSO an epoch-boundary
 * operation but lives in Phase 10 / Task 51; only a TODO hook is
 * present here.
 *
 * Synthetic UTXOs emitted at the boundary are not tied to a specific
 * TX hash (no TX triggered them). We derive a deterministic
 * pseudo-tx_hash as
 *   SHA3-512("dnac_epoch_graduation_v1" || block_height[8 BE])
 * which cannot collide with any real TX hash (real TX hashes are
 * SHA3-512 over canonical TX preimage) and is deterministic across all
 * witnesses for the same block.
 *
 * Returns 0 on success (including the no-op non-boundary path), -1 on
 * any failure — caller (finalize_block) should propagate the error so
 * the outer transaction rolls back.
 */
static int apply_epoch_boundary_transitions(nodus_witness_t *w,
                                               uint64_t block_height) {
    if (!w || !w->db) return -1;

    /* Epoch-boundary check. block_height==0 would be pre-genesis; the
     * first real epoch boundary is DNAC_EPOCH_LENGTH itself. */
    if (block_height == 0 || (block_height % DNAC_EPOCH_LENGTH) != 0) {
        return 0;
    }

    /* Derive deterministic pseudo-tx_hash for synthetic UTXOs. */
    uint8_t boundary_tx_hash[64];
    {
        static const char tag[] = "dnac_epoch_graduation_v1";
        const size_t tag_len = sizeof(tag) - 1;  /* exclude NUL */
        uint8_t preimage[32 + 8];
        memset(preimage, 0, sizeof(preimage));
        memcpy(preimage, tag, tag_len);
        /* Big-endian encoding of block_height in last 8 bytes. */
        for (int i = 0; i < 8; i++) {
            preimage[32 + i] =
                (uint8_t)((block_height >> (56 - 8 * i)) & 0xff);
        }
        qgp_sha3_512(preimage, sizeof(preimage), boundary_tx_hash);
    }

    /* ─────── 1. Pending commission activation ─────── */
    {
        sqlite3_stmt *stmt = NULL;
        const char *sql =
            "UPDATE validators "
            "SET commission_bps = pending_commission_bps, "
            "    pending_commission_bps = 0, "
            "    pending_effective_block = 0 "
            "WHERE pending_effective_block = ? "
            "  AND pending_commission_bps != 0";
        int rc = sqlite3_prepare_v2(w->db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s: epoch_boundary: prepare pending_commission failed: %s\n",
                    LOG_TAG, sqlite3_errmsg(w->db));
            return -1;
        }
        sqlite3_bind_int64(stmt, 1, (int64_t)block_height);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "%s: epoch_boundary: exec pending_commission failed (rc=%d): %s\n",
                    LOG_TAG, rc, sqlite3_errmsg(w->db));
            return -1;
        }
    }

    /* ─────── 2. RETIRING → UNSTAKED graduation ─────── */
    {
        /* Collect candidate pubkeys first — we cannot hold a SELECT stmt
         * open across the subsequent UPDATEs on the same table. */
        typedef struct {
            uint8_t pubkey[DNAC_PUBKEY_SIZE];
        } graduate_t;
        graduate_t *candidates = NULL;
        size_t candidate_count = 0, candidate_cap = 0;

        sqlite3_stmt *sel = NULL;
        int rc = sqlite3_prepare_v2(
            w->db,
            /* S3 (ORCHESTRATOR integration): ORDER BY is load-bearing —
             * the loop below assigns per-graduate output_index values, so
             * the iteration order must be a stable total key on every
             * node, never table-scan order. */
            "SELECT pubkey FROM validators WHERE status = ? "
            "ORDER BY pubkey ASC",
            -1, &sel, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s: epoch_boundary: prepare RETIRING select failed: %s\n",
                    LOG_TAG, sqlite3_errmsg(w->db));
            return -1;
        }
        sqlite3_bind_int(sel, 1, (int)DNAC_VALIDATOR_RETIRING);
        while ((rc = sqlite3_step(sel)) == SQLITE_ROW) {
            const void *pk = sqlite3_column_blob(sel, 0);
            int pk_len = sqlite3_column_bytes(sel, 0);
            if (!pk || pk_len != DNAC_PUBKEY_SIZE) {
                fprintf(stderr, "%s: epoch_boundary: RETIRING pubkey wrong size (%d)\n",
                        LOG_TAG, pk_len);
                sqlite3_finalize(sel);
                free(candidates);
                return -1;
            }
            if (candidate_count == candidate_cap) {
                size_t new_cap = candidate_cap ? candidate_cap * 2 : 8;
                graduate_t *grown = realloc(candidates,
                                              new_cap * sizeof(graduate_t));
                if (!grown) {
                    fprintf(stderr, "%s: epoch_boundary: OOM collecting RETIRING\n",
                            LOG_TAG);
                    sqlite3_finalize(sel);
                    free(candidates);
                    return -1;
                }
                candidates = grown;
                candidate_cap = new_cap;
            }
            memcpy(candidates[candidate_count].pubkey, pk, DNAC_PUBKEY_SIZE);
            candidate_count++;
        }
        sqlite3_finalize(sel);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "%s: epoch_boundary: RETIRING select step failed (rc=%d): %s\n",
                    LOG_TAG, rc, sqlite3_errmsg(w->db));
            free(candidates);
            return -1;
        }

        /* Per-graduate: emit principal UTXO, flip status, dec stat.
         * (v0.16: reward auto-claim on graduation removed — push-settlement
         * distributes rewards at epoch boundary independently of RETIRING
         * graduation.) */
        for (size_t i = 0; i < candidate_count; i++) {
            const uint8_t *val_pubkey = candidates[i].pubkey;

            dnac_validator_record_t v;
            rc = nodus_validator_get(w, val_pubkey, &v);
            if (rc != 0) {
                fprintf(stderr, "%s: epoch_boundary: validator_get failed (rc=%d)\n",
                        LOG_TAG, rc);
                free(candidates);
                return -1;
            }

            /* Emit the principal locked UTXO (kind 0x10) — unlock_block =
             * block_height + cooldown.
             *
             * S3: the amount is the validator record's ACTUAL self_stake,
             * not the DNAC_SELF_STAKE_AMOUNT literal. With extra self-bond
             * allowed (apply_stake computes the bond from the TX's native
             * flow), paying back the literal would either strand the
             * surplus or mint from nothing — and the supply invariant sums
             * validators.self_stake, so the ledger would refuse the block
             * either way. Today every bond equals the literal, so the
             * emitted amount is unchanged on the live chain. */
            /* S3 (ORCHESTRATOR integration): output_index is 200 + i, not
             * the literal 200 — two graduates in one boundary used to
             * derive IDENTICAL synthetic nullifiers from
             * (boundary_tx_hash, 200) and the second payout collided.
             * i is deterministic because the candidate SELECT above is
             * ORDER BY pubkey ASC. Range stays clear of neighbours:
             * UNDELEGATE uses 100-101, settlement starts at 400
             * (NODUS_EPOCH_SETTLE_OUTPUT_INDEX_BASE), and i < 128
             * (DNAC_MAX_VALIDATORS caps the table) ⇒ 200..327. */
            if (emit_synthetic_utxo_for_fp(
                    w, boundary_tx_hash,
                    (const char *)v.unstake_destination_fp,
                    v.self_stake,
                    block_height,
                    /*kind=*/0x10,
                    /*output_index=*/(uint32_t)(200 + i),
                    /*unlock_block=*/block_height + DNAC_UNSTAKE_COOLDOWN_BLOCKS)
                != 0) {
                fprintf(stderr, "%s: epoch_boundary: emit principal UTXO failed\n",
                        LOG_TAG);
                free(candidates);
                return -1;
            }

            /* Transition RETIRING → UNSTAKED, and ZERO the bond.
             *
             * S3 (ORCHESTRATOR integration): the bond's value just moved
             * into the principal UTXO above; leaving it on the record too
             * double-counts it in check_supply_invariant_v016's
             * Σ self_stake term (that SUM has no status filter) and the
             * very block performing the graduation would be rejected.
             * This was a latent halt on the FIRST-EVER graduation — the
             * cooldown (17280 blocks) is longer than any test run, so the
             * path had never executed end-to-end. validator.h has always
             * documented self_stake as "zeroed post-UNSTAKE"; the code
             * now implements its own contract. */
            v.status = (uint8_t)DNAC_VALIDATOR_UNSTAKED;
            v.self_stake = 0;
            rc = nodus_validator_update(w, &v);
            if (rc != 0) {
                fprintf(stderr, "%s: epoch_boundary: validator_update failed (rc=%d)\n",
                        LOG_TAG, rc);
                free(candidates);
                return -1;
            }

            /* Decrement active_count. A RETIRING validator was already
             * subtracted from the committee by status filter but
             * active_count still reflected the STAKE bump; graduation
             * is when the counter actually drops. */
            char *err = NULL;
            int src = sqlite3_exec(w->db,
                "UPDATE validator_stats SET value = value - 1 "
                "WHERE key = 'active_count'",
                NULL, NULL, &err);
            if (src != SQLITE_OK) {
                fprintf(stderr, "%s: epoch_boundary: active_count dec failed: %s\n",
                        LOG_TAG, err ? err : "(null)");
                if (err) sqlite3_free(err);
                free(candidates);
                return -1;
            }
        }

        free(candidates);
    }

    /* ─────── 3. Liveness-based AUTO_RETIRED ─────── */
    /* Phase 9 / Task 48 — liveness attendance transition.
     *
     * Per design §3 (Rule N): a validator that misses the liveness
     * threshold for DNAC_AUTO_RETIRE_EPOCHS consecutive epochs is
     * auto-retired. The per-block attendance watermark
     * (validator.last_signed_block) is maintained by
     * nodus_witness_record_attendance (called after cert_store in the
     * BFT commit path). Here at the epoch boundary we read that
     * watermark to decide who attended the past epoch.
     *
     * Semantics (v1 simplification): "present" == signed ANY block in
     * the past epoch. This is stricter than the 80% threshold in
     * design §3.5 (a validator that signed 95/120 is treated the same
     * as one that signed 120/120) but it is a safe
     * over-approximation: anyone counted "present" here would also
     * clear the 80% bar. The DNAC_LIVENESS_THRESHOLD_BPS constant is
     * retained for the accumulator-side liveness gate in Task 49.
     *
     * A future v2 refinement would add a per-epoch signed-block
     * counter to validator_stats and compare against
     * DNAC_LIVENESS_THRESHOLD_BPS exactly. */
    {
        uint64_t epoch_start = 0;
        if (block_height > DNAC_EPOCH_LENGTH) {
            epoch_start = block_height - DNAC_EPOCH_LENGTH;
        }

        /* Step 3a: increment consecutive_missed_epochs — S3 fix: ONLY for
         * the past epoch's BASE LEADER, and only if it never signed.
         *
         * ⚠ Found by the S3 7→9→7 harness (pre-existing, latent): the
         * attendance watermark is written by record_attendance for the
         * block PROPOSER alone (the precommit voter set is node-local and
         * non-deterministic — see its comment), while the leader is
         * (epoch + view) % n — ONE base proposer per EPOCH. Blaming every
         * ACTIVE validator whose watermark is stale therefore auto-retired
         * ALL non-leaders after DNAC_AUTO_RETIRE_EPOCHS (observed live in
         * the harness: 6 of 9 validators AUTO_RETIRED by epoch 5). No real
         * chain had ever crossed enough boundaries for this to fire — the
         * live devnet (E = 720) has never reached block 2880.
         *
         * A validator can only MISS an epoch in which it HAD a proposer
         * slot. The base leader for the past epoch is deterministic from
         * committed state (committee(epoch_start) + (epoch_num % n)), so
         * every node blames the same validator or none. A leader that was
         * view-changed around all epoch keeps a stale watermark and is
         * rightly blamed; everyone else has no slot and no blame. Rule N
         * still evicts persistently dead LEADERS, which is its purpose. */
        const uint8_t *past_leader_pk = NULL;
        nodus_committee_member_t *past_cm = NULL;
        {
            int past_n = 0;
            if (nodus_committee_get_for_block_alloc(w, epoch_start,
                                                    &past_cm, &past_n) != 0) {
                fprintf(stderr, "%s: epoch_boundary: past-epoch committee "
                        "lookup failed — cannot run Rule N\n", LOG_TAG);
                return -1;
            }
            if (past_n > 0) {
                uint64_t epoch_num = epoch_start / (uint64_t)DNAC_EPOCH_LENGTH;
                past_leader_pk =
                    past_cm[(size_t)(epoch_num % (uint64_t)past_n)].pubkey;
            }
            /* past_n == 0: pre-genesis fixture epochs — nobody had a
             * slot, nobody is blamed. */
        }
        int rc;
        if (past_leader_pk) {
            sqlite3_stmt *inc = NULL;
            rc = sqlite3_prepare_v2(w->db,
                "UPDATE validators "
                "SET consecutive_missed_epochs = consecutive_missed_epochs + 1 "
                "WHERE status = ? AND last_signed_block < ? "
                "  AND active_since_block + ? <= ? "
                "  AND pubkey = ?",
                -1, &inc, NULL);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "%s: epoch_boundary: prepare miss_inc failed: %s\n",
                        LOG_TAG, sqlite3_errmsg(w->db));
                free(past_cm);
                return -1;
            }
            sqlite3_bind_int(inc, 1, (int)DNAC_VALIDATOR_ACTIVE);
            sqlite3_bind_int64(inc, 2, (int64_t)epoch_start);
            /* MIN_TENURE gate: a validator that just staked in the epoch
             * being evaluated cannot be blamed for missing it. */
            sqlite3_bind_int64(inc, 3, (int64_t)DNAC_MIN_TENURE_BLOCKS);
            sqlite3_bind_int64(inc, 4, (int64_t)block_height);
            sqlite3_bind_blob(inc, 5, past_leader_pk, DNAC_PUBKEY_SIZE,
                              SQLITE_STATIC);
            rc = sqlite3_step(inc);
            sqlite3_finalize(inc);
        } else {
            rc = SQLITE_DONE;   /* no slot existed → no blame this epoch */
        }
        free(past_cm);
        past_cm = NULL;
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "%s: epoch_boundary: miss_inc step failed (rc=%d)\n",
                    LOG_TAG, rc);
            return -1;
        }

        sqlite3_stmt *rst = NULL;
        rc = sqlite3_prepare_v2(w->db,
            "UPDATE validators SET consecutive_missed_epochs = 0 "
            "WHERE status = ? AND last_signed_block >= ?",
            -1, &rst, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s: epoch_boundary: prepare miss_reset failed: %s\n",
                    LOG_TAG, sqlite3_errmsg(w->db));
            return -1;
        }
        sqlite3_bind_int(rst, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(rst, 2, (int64_t)epoch_start);
        rc = sqlite3_step(rst);
        sqlite3_finalize(rst);
        if (rc != SQLITE_DONE) {
            fprintf(stderr, "%s: epoch_boundary: miss_reset step failed (rc=%d)\n",
                    LOG_TAG, rc);
            return -1;
        }

        /* Step 3b: flip ACTIVE validators that crossed
         * DNAC_AUTO_RETIRE_EPOCHS to AUTO_RETIRED. Count the flipped
         * rows so active_count can be decremented once per flip. */
        sqlite3_stmt *count = NULL;
        rc = sqlite3_prepare_v2(w->db,
            "SELECT COUNT(*) FROM validators "
            "WHERE status = ? AND consecutive_missed_epochs >= ?",
            -1, &count, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "%s: epoch_boundary: prepare auto_retire count failed\n",
                    LOG_TAG);
            return -1;
        }
        sqlite3_bind_int(count, 1, (int)DNAC_VALIDATOR_ACTIVE);
        sqlite3_bind_int64(count, 2, (int64_t)DNAC_AUTO_RETIRE_EPOCHS);
        int retire_count = 0;
        if (sqlite3_step(count) == SQLITE_ROW)
            retire_count = sqlite3_column_int(count, 0);
        sqlite3_finalize(count);

        if (retire_count > 0) {
            sqlite3_stmt *ar = NULL;
            rc = sqlite3_prepare_v2(w->db,
                "UPDATE validators SET status = ? "
                "WHERE status = ? AND consecutive_missed_epochs >= ?",
                -1, &ar, NULL);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "%s: epoch_boundary: prepare auto_retire failed\n",
                        LOG_TAG);
                return -1;
            }
            sqlite3_bind_int(ar, 1, (int)DNAC_VALIDATOR_AUTO_RETIRED);
            sqlite3_bind_int(ar, 2, (int)DNAC_VALIDATOR_ACTIVE);
            sqlite3_bind_int64(ar, 3, (int64_t)DNAC_AUTO_RETIRE_EPOCHS);
            rc = sqlite3_step(ar);
            sqlite3_finalize(ar);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "%s: epoch_boundary: auto_retire step failed (rc=%d)\n",
                        LOG_TAG, rc);
                return -1;
            }

            /* Decrement validator_stats.active_count by retire_count.
             * Using a parameterized UPDATE to avoid embedding a raw
             * integer in the SQL string. */
            sqlite3_stmt *dec = NULL;
            rc = sqlite3_prepare_v2(w->db,
                "UPDATE validator_stats "
                "SET value = value - ? WHERE key = 'active_count'",
                -1, &dec, NULL);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "%s: epoch_boundary: prepare active_count dec failed\n",
                        LOG_TAG);
                return -1;
            }
            sqlite3_bind_int64(dec, 1, (int64_t)retire_count);
            rc = sqlite3_step(dec);
            sqlite3_finalize(dec);
            if (rc != SQLITE_DONE) {
                fprintf(stderr, "%s: epoch_boundary: active_count dec step failed (rc=%d)\n",
                        LOG_TAG, rc);
                return -1;
            }

            QGP_LOG_INFO(LOG_TAG,
                "auto-retired %d validator(s) at epoch boundary block %llu",
                retire_count, (unsigned long long)block_height);
        }
    }

    /* ─────── 4. Committee election for next epoch ─────── */
    /* Phase 10 / Task 51-53 — committee election is demand-driven
     * through nodus_committee_get_for_block(), which caches per-epoch
     * on w->cached_committee_* and consumes the post-commit lookback
     * snapshot defined in §3.6. BFT roster wiring (Task 59) consumes
     * the same accessor. */

    /* ─────── 5. S3 validator-set lifecycle ───────
     *
     * ORDER IS LOAD-BEARING. The full boundary sequence is now:
     *
     *   1. pending-commission activation
     *   2. RETIRING → UNSTAKED graduation (+ active_count decrement)
     *   3. Rule N liveness: miss-increment / reset / AUTO_RETIRE
     *   4. (committee election — demand-driven, no work here)
     *   5a. apply_boundary_flips   ← THIS EPOCH's membership
     *   5b. commit_next            ← NEXT EPOCH's frozen set
     *
     * 5a runs after 1-3 so the flips see the final bonded set for this
     * boundary (a validator that graduated or auto-retired in step 2/3 is
     * no longer ACTIVE/ELIGIBLE and is therefore not flipped at all).
     *
     * 5b runs after 5a because it RANKS over the post-flip state:
     * nodus_validator_top_n selects on status IN (ACTIVE, ELIGIBLE), so
     * running it first would rank against the previous epoch's status
     * assignment. Ranking after the flips makes the (k+1)E snapshot a
     * function of the state this block actually committed.
     *
     * Both live inside finalize_block's transaction, so the BFT-original
     * path, the genesis path and the sync-replay path all execute them
     * identically — the same reason this whole function lives here rather
     * than in a commit wrapper. Either failing returns -1, which
     * finalize_block propagates into the caller's rollback: no partial
     * membership change is ever committed, and the node simply does not
     * vote for the block. */
    if (nodus_witness_vset_apply_boundary_flips(w, block_height) != 0) {
        fprintf(stderr,
                "%s: epoch_boundary: validator-set flips failed at h=%llu\n",
                LOG_TAG, (unsigned long long)block_height);
        return -1;
    }
    if (nodus_witness_vset_commit_next(w, block_height) != 0) {
        fprintf(stderr,
                "%s: epoch_boundary: next-epoch validator-set commit failed "
                "at h=%llu\n", LOG_TAG, (unsigned long long)block_height);
        return -1;
    }

    /* O15J Faz 3 — step 6 was the O15C activation state machine
     * (SCHEDULED→READY→ACTIVE at the epoch boundary). It is deleted with
     * the ceremony: no boundary flips a chain from V1 to V2 any more,
     * because a V2 chain is born V2. */

    return 0;
}

/* v0.16: apply_accumulator_update removed. The accumulator/residual-dust
 * u128 reward-distribution model has been replaced by the push-per-epoch
 * UTXO settlement arriving in Stage E (apply_epoch_settlement). TX fees
 * now burn directly to total_burned; validator rewards come from
 * inflation mint only, distributed atomically at block_height % 120 == 0. */

/* ── Stage E — apply_epoch_settlement ─────────────────────────────────
 *
 * Fires at finalize_block whenever block_height > 0 &&
 * block_height % DNAC_EPOCH_LENGTH == 0 — i.e. the first block of a
 * new epoch. Settles the epoch that JUST ENDED (settling_epoch_start
 * = block_height − DNAC_EPOCH_LENGTH).
 *
 * Reads the snapshot_blob captured at epoch start (Stage D.1) —
 * committee list + per-delegation amounts — and drains
 * epoch_state.epoch_pool_accum into UTXOs + burn according to the
 * design §3.4 pseudocode:
 *
 *   per_slot   = pool / committee_count
 *   outer_dust = pool − per_slot * committee_count → burn (D8)
 *
 *   for each committee validator V:
 *     if V did NOT sign ANY block in the epoch:
 *       per_slot → burn  (D7 offline-share)
 *       continue
 *     if V has no delegations:
 *       emit_utxo(V.pubkey, per_slot)
 *     else:
 *       total_stake = V.self_stake + V.total_delegated
 *       validator_base  = per_slot * V.self_stake / total_stake
 *       delegator_gross = per_slot − validator_base
 *       commission      = delegator_gross * V.commission_bps / 10000
 *       validator_total = validator_base + commission
 *       delegator_net   = delegator_gross − commission
 *       for each delegation D of V (snapshot):
 *         share = delegator_net * D.amount / V.total_delegated
 *         emit_utxo(D.delegator_pubkey, share)
 *       inner_dust = delegator_net − Σ shares → burn
 *       emit_utxo(V.pubkey, validator_total)
 *
 *   delete epoch_state[settling_epoch_start]
 *
 * Attendance check (D6) — CORRECTED 2026-08-27. This block used to
 * describe a `validator.last_signed_block` window check, and argued the
 * two were "equivalent in practice". THAT IS NOT WHAT THE CODE DOES,
 * and the argument is the exact one the code below rejects.
 *
 * The implementing lines are :3253-3262. They read
 * `signed_blocks_this_epoch` and require
 *
 *     signed_blocks_this_epoch * committee_count * 10000
 *         >= DNAC_EPOCH_LENGTH * DNAC_LIVENESS_THRESHOLD_BPS
 *
 * i.e. the validator must have proposed at least
 * DNAC_LIVENESS_THRESHOLD_BPS/10000 of the slots its committee size
 * entitled it to, with `settling_epoch_start == 0` carved out as
 * unconditionally present.
 *
 * The block around :3205-3215 records WHY the binary last-signed check
 * was replaced: it let a validator take ~83% planned downtime and still
 * be paid. A
 * reader who trusted the old wording would re-introduce that defect —
 * and one nearly did (O15J Faz 2, ported from this comment before the
 * code was read).
 */
static uint32_t be32_load(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}
static uint16_t be16_load(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}
static uint64_t be64_load(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | (uint64_t)p[i];
    return v;
}

/* Settlement-UTXO tx_hash derivation: deterministic per epoch boundary.
 *   tx_hash = SHA3-512("settlement" || epoch_start_height BE)
 * Collision-free with any real TX hash (which is SHA3-512 over full
 * TX body) modulo second-preimage resistance. */
static void settlement_tx_hash(uint64_t settling_epoch_start,
                                uint8_t out[64]) {
    uint8_t preimage[10 + 8];
    memcpy(preimage, "settlement", 10);
    for (int i = 7; i >= 0; i--) {
        preimage[10 + i] = (uint8_t)(settling_epoch_start & 0xff);
        settling_epoch_start >>= 8;
    }
    qgp_sha3_512(preimage, sizeof(preimage), out);
}

/* Scan the delegations portion of the snapshot for rows whose
 * validator_pubkey matches `validator_pubkey`. Caller owns
 * dels_out — an array sized by the total delegation_count in the
 * snapshot.
 *
 * Returns count written into dels_out / amount_out.
 */
typedef struct {
    uint8_t  delegator_pubkey[DNAC_PUBKEY_SIZE];
    uint64_t amount;
} settlement_deleg_t;

static int collect_delegations_for_validator(
    const uint8_t *deleg_base, uint32_t deleg_count,
    const uint8_t *validator_pubkey,
    settlement_deleg_t *out, int max_out) {
    const size_t per_row = DNAC_PUBKEY_SIZE + DNAC_PUBKEY_SIZE + 8;
    int written = 0;
    for (uint32_t i = 0; i < deleg_count && written < max_out; i++) {
        const uint8_t *row = deleg_base + (size_t)i * per_row;
        const uint8_t *dpk = row;
        const uint8_t *vpk = row + DNAC_PUBKEY_SIZE;
        if (memcmp(vpk, validator_pubkey, DNAC_PUBKEY_SIZE) != 0) continue;
        uint64_t amt = be64_load(row + 2 * DNAC_PUBKEY_SIZE);
        memcpy(out[written].delegator_pubkey, dpk, DNAC_PUBKEY_SIZE);
        out[written].amount = amt;
        written++;
    }
    return written;
}

/* Output-index reservation: one epoch's settlement may emit up to
 * 7 committee validators × 65 (1 commission + 64 delegations) = 455
 * UTXOs. We start synthetic output_index at 400 to stay clear of the
 * UNDELEGATE principal/reward range (100-101) and the
 * apply_epoch_boundary_transitions RETIRING graduation range
 * (200 + i, i < DNAC_MAX_VALIDATORS ⇒ 200-327). */
#define NODUS_EPOCH_SETTLE_OUTPUT_INDEX_BASE 400

/* Settlement-loop-optimised variant of emit_synthetic_utxo that reuses a
 * pre-prepared INSERT statement. Avoids the ~100µs sqlite3_prepare_v2
 * per row; at N=10K delegators this is ~1 s of block latency saved. The
 * caller is responsible for preparing `stmt` once before the loop and
 * finalizing after. Identical semantics to emit_synthetic_utxo: same
 * nullifier derivation, same owner-fp encoding, same UTXO row fields. */
static int emit_synthetic_utxo_cached(nodus_witness_t *w,
                                        sqlite3_stmt *stmt,
                                        const uint8_t *tx_hash,
                                        const uint8_t *owner_pubkey,
                                        uint64_t amount,
                                        uint64_t block_height,
                                        uint8_t kind_byte,
                                        uint32_t output_index,
                                        uint64_t unlock_block) {
    /* Derive synthetic nullifier: SHA3-512(tx_hash || kind || index_be). */
    uint8_t preimage[64 + 1 + 4];
    memcpy(preimage, tx_hash, 64);
    preimage[64] = kind_byte;
    preimage[65] = (uint8_t)((output_index >> 24) & 0xff);
    preimage[66] = (uint8_t)((output_index >> 16) & 0xff);
    preimage[67] = (uint8_t)((output_index >> 8) & 0xff);
    preimage[68] = (uint8_t)(output_index & 0xff);
    uint8_t nullifier[64];
    qgp_sha3_512(preimage, sizeof(preimage), nullifier);

    /* Owner fingerprint = hex-encoded SHA3-512(owner_pubkey). */
    uint8_t owner_fp_raw[QGP_FP_RAW_BYTES];
    qgp_sha3_512(owner_pubkey, DNAC_PUBKEY_SIZE, owner_fp_raw);
    char owner_fp_hex[QGP_FP_HEX_BUFFER];
    qgp_fp_raw_to_hex(owner_fp_raw, owner_fp_hex);

    /* Native DNAC token_id = 64 zeros. */
    static const uint8_t zero_token_id[64] = {0};

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    sqlite3_bind_blob(stmt, 1, nullifier, NODUS_T3_NULLIFIER_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, owner_fp_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, (int64_t)amount);
    sqlite3_bind_blob(stmt, 4, zero_token_id, 64, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 5, tx_hash, NODUS_T3_TX_HASH_LEN, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, (int)output_index);
    sqlite3_bind_int64(stmt, 7, (int64_t)block_height);
    sqlite3_bind_int64(stmt, 8, (int64_t)time(NULL));
    sqlite3_bind_int64(stmt, 9, (int64_t)unlock_block);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr,
                "%s: emit_synthetic_utxo_cached: step failed (rc=%d, kind=0x%02x, idx=%u): %s\n",
                LOG_TAG, rc, kind_byte, output_index,
                sqlite3_errmsg(w->db));
        return -1;
    }
    return 0;
}

static int apply_epoch_settlement(nodus_witness_t *w,
                                    uint64_t settling_epoch_start) {
    if (!w || !w->db) return -1;

    /* Load the epoch_state row for the settling epoch. Missing row is
     * fine — nothing to settle (first boundary in a fresh chain). */
    nodus_epoch_state_t es = {0};
    int grc = nodus_witness_epoch_get(w, settling_epoch_start, &es);
    if (grc != 0) return 0;

    uint64_t pool = es.epoch_pool_accum;
    const uint8_t *blob = es.snapshot_blob;
    size_t blob_len = es.snapshot_blob_len;

    /* Canonical empty snapshot (Stage D.2) is 6 bytes: 0x0000 || 0x00000000.
     * In that case there's no committee to distribute to — burn the
     * whole pool (keeps supply bookkeeping closed) and retire the row. */
    if (!blob || blob_len < 6) {
        if (pool > 0) nodus_witness_supply_add_burned(w, pool, es.snapshot_hash);
        nodus_witness_epoch_free(&es);
        nodus_witness_epoch_delete(w, settling_epoch_start);
        return 0;
    }

    size_t off = 0;
    uint16_t committee_count = be16_load(blob + off); off += 2;

    const size_t VAL_ROW = DNAC_PUBKEY_SIZE + 8 + 8 + 2 + 1;  /* 2611 */
    if (off + (size_t)committee_count * VAL_ROW + 4 > blob_len) {
        fprintf(stderr, "%s: epoch_settlement: truncated snapshot_blob\n",
                LOG_TAG);
        nodus_witness_epoch_free(&es);
        return -1;
    }
    const uint8_t *val_base = blob + off;
    off += (size_t)committee_count * VAL_ROW;

    uint32_t deleg_count = be32_load(blob + off); off += 4;
    const size_t DEL_ROW = DNAC_PUBKEY_SIZE + DNAC_PUBKEY_SIZE + 8;  /* 5192 */
    if (off + (size_t)deleg_count * DEL_ROW > blob_len) {
        fprintf(stderr, "%s: epoch_settlement: truncated snapshot delegations\n",
                LOG_TAG);
        nodus_witness_epoch_free(&es);
        return -1;
    }
    const uint8_t *deleg_base = blob + off;

    if (committee_count == 0) {
        /* Empty committee but non-zero pool → burn it all. */
        if (pool > 0) nodus_witness_supply_add_burned(w, pool, es.snapshot_hash);
        nodus_witness_epoch_free(&es);
        nodus_witness_epoch_delete(w, settling_epoch_start);
        return 0;
    }

    uint64_t per_slot = pool / (uint64_t)committee_count;
    uint64_t outer_dust = pool - per_slot * (uint64_t)committee_count;

    uint8_t tx_hash[64];
    settlement_tx_hash(settling_epoch_start, tx_hash);

    uint32_t out_idx = NODUS_EPOCH_SETTLE_OUTPUT_INDEX_BASE;
    uint64_t total_burned_here = outer_dust;

    /* Temporary buffer for per-validator delegation list — sized to
     * the worst case (all delegations belong to one validator). */
    settlement_deleg_t *dels = NULL;
    if (deleg_count > 0) {
        dels = calloc(deleg_count, sizeof(*dels));
        if (!dels) {
            nodus_witness_epoch_free(&es);
            return -1;
        }
    }

    /* Cache the utxo INSERT statement across the emit loop — at N=10K
     * delegators the per-row sqlite3_prepare_v2 dominates settlement
     * block latency. Prepared once here, reused via reset+bind+step,
     * finalized at every exit path below. */
    sqlite3_stmt *utxo_ins_stmt = NULL;
    {
        int prc = sqlite3_prepare_v2(w->db,
            "INSERT OR IGNORE INTO utxo_set "
            "(nullifier, owner, amount, token_id, tx_hash, output_index, "
            " block_height, created_at, unlock_block) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            -1, &utxo_ins_stmt, NULL);
        if (prc != SQLITE_OK) {
            fprintf(stderr,
                    "%s: epoch_settlement: prepare utxo_add failed: %s\n",
                    LOG_TAG, sqlite3_errmsg(w->db));
            free(dels);
            nodus_witness_epoch_free(&es);
            return -1;
        }
    }

    for (uint16_t vi = 0; vi < committee_count; vi++) {
        const uint8_t *vrow = val_base + (size_t)vi * VAL_ROW;
        const uint8_t *vpk = vrow;
        uint64_t self_stake      = be64_load(vrow + DNAC_PUBKEY_SIZE);
        uint64_t total_delegated = be64_load(vrow + DNAC_PUBKEY_SIZE + 8);
        uint16_t commission_bps  = be16_load(vrow + DNAC_PUBKEY_SIZE + 16);
        /* status byte at vrow + 2610 — unused here (RETIRING members stay
         * in committee for the epoch per design §3.6). */

        /* Attendance gate (D6, SEC-01 mitigation).
         *
         * Historical v0.16 design used a binary "signed at least one
         * block in the epoch range" check. Under EPOCH_LENGTH=720 that
         * allowed 83% planned downtime per epoch (drive-by attacker
         * signs one block, earns full hour). This gate replaces it
         * with a count-based 80%-of-expected-proposer-slots threshold:
         *
         *   per-validator expected proposer slots per epoch
         *     = EPOCH_LENGTH / active_set_size (round-robin leader).
         *   required slots = expected * LIVENESS_THRESHOLD_BPS / 10000.
         *   present if signed_blocks_this_epoch >= required.
         *
         * Rearranged for exact integer math (no division, no truncation):
         *   signed * active_set_size * 10000 >= EPOCH_LENGTH * THRESHOLD_BPS.
         *
         * ── S3: THE DENOMINATOR IS THE EPOCH'S OWN SET SIZE ────────────
         * This used to be the DNAC_COMMITTEE_SIZE literal. With a dynamic
         * active set that literal is simply the WRONG number: at 21 seats
         * the round-robin gives each member ~EPOCH_LENGTH/21 proposal
         * slots, so requiring 80% of EPOCH_LENGTH/7 would burn every
         * honest validator's share.
         *
         * `committee_count` is the size of the set THIS epoch actually
         * had: it is decoded from the epoch_state snapshot_blob captured
         * at the epoch's first block by nodus_witness_epoch_snapshot_apply
         * (nodus_witness_epoch.c:299) and is the very list being iterated
         * here. It is therefore (a) the historical value, not a
         * current-set substitution, and (b) byte-identical on every node,
         * because the snapshot is part of the committed epoch_state row
         * that feeds state_root. Guaranteed non-zero: the
         * committee_count == 0 early return above already handled that.
         *
         * On the live 7-seat chain committee_count == 7, so the product
         * is unchanged.
         *
         * The counter is incremented by nodus_witness_record_attendance
         * only for the block proposer (deterministic across all nodes
         * because proposer_id is in the committed block header).
         *
         * Genesis special-case: at the very first settlement
         * (settling_epoch_start == 0), every genesis-seeded validator
         * has signed_blocks_this_epoch = 0 but genuinely participated.
         * Treat all committee members as present for the bootstrap
         * epoch to avoid burning the entire first-hour pool. */
        dnac_validator_record_t current_v;
        bool present = false;
        if (settling_epoch_start == 0) {
            present = true;
        } else if (nodus_validator_get(w, vpk, &current_v) == 0) {
            uint64_t lhs = current_v.signed_blocks_this_epoch *
                           (uint64_t)committee_count * 10000ULL;
            uint64_t rhs = (uint64_t)DNAC_EPOCH_LENGTH *
                           (uint64_t)DNAC_LIVENESS_THRESHOLD_BPS;
            if (lhs >= rhs) {
                present = true;
            }
        }
        if (!present) {
            total_burned_here += per_slot;
            continue;
        }

        if (per_slot == 0) continue;  /* pool too small to split */

        if (total_delegated == 0 || deleg_count == 0) {
            /* Pure validator share. */
            if (emit_synthetic_utxo_cached(w, utxo_ins_stmt, tx_hash,
                                             vpk, per_slot,
                                             settling_epoch_start,
                                             /*kind=*/0x20,
                                             out_idx++, /*unlock=*/0) != 0) {
                sqlite3_finalize(utxo_ins_stmt);
                free(dels);
                nodus_witness_epoch_free(&es);
                return -1;
            }
            continue;
        }

        uint64_t total_stake = self_stake + total_delegated;
        if (total_stake == 0) total_stake = 1;   /* defensive */

        /* Use u128 for the multiply to avoid overflow. */
        qgp_u128_t num = qgp_u128_from_u64(per_slot);
        num = qgp_u128_mul_u64(num, self_stake);
        uint64_t rem = 0;
        qgp_u128_t q = qgp_u128_div_u64(num, total_stake, &rem);
        uint64_t validator_base = q.lo;   /* high limb provably 0 here
                                             since per_slot * self_stake
                                             < 2^128 and /total_stake
                                             compresses further */

        uint64_t delegator_gross = (per_slot > validator_base)
                                    ? (per_slot - validator_base) : 0;

        uint64_t commission = 0;
        if (commission_bps > 0 && delegator_gross > 0) {
            qgp_u128_t cn = qgp_u128_from_u64(delegator_gross);
            cn = qgp_u128_mul_u64(cn, (uint64_t)commission_bps);
            qgp_u128_t cq = qgp_u128_div_u64(cn, 10000ULL, &rem);
            commission = cq.lo;
            if (commission > delegator_gross) commission = delegator_gross;
        }
        uint64_t validator_total = validator_base + commission;
        uint64_t delegator_net   = delegator_gross - commission;

        /* Collect this validator's delegations from snapshot. */
        int n_dels = collect_delegations_for_validator(
            deleg_base, deleg_count, vpk, dels, (int)deleg_count);

        uint64_t distributed = 0;
        for (int di = 0; di < n_dels; di++) {
            /* share = delegator_net * D.amount / total_delegated */
            qgp_u128_t sn = qgp_u128_from_u64(delegator_net);
            sn = qgp_u128_mul_u64(sn, dels[di].amount);
            qgp_u128_t sq = qgp_u128_div_u64(sn, total_delegated, &rem);
            uint64_t share = sq.lo;

            if (share > 0) {
                if (emit_synthetic_utxo_cached(w, utxo_ins_stmt, tx_hash,
                                                 dels[di].delegator_pubkey,
                                                 share, settling_epoch_start,
                                                 /*kind=*/0x21,
                                                 out_idx++, /*unlock=*/0) != 0) {
                    sqlite3_finalize(utxo_ins_stmt);
                    free(dels);
                    nodus_witness_epoch_free(&es);
                    return -1;
                }
                distributed += share;
            }
        }
        if (distributed > delegator_net) distributed = delegator_net;
        uint64_t inner_dust = delegator_net - distributed;
        total_burned_here += inner_dust;

        /* Validator's consolidated UTXO (base + commission). */
        if (validator_total > 0) {
            if (emit_synthetic_utxo_cached(w, utxo_ins_stmt, tx_hash,
                                             vpk, validator_total,
                                             settling_epoch_start,
                                             /*kind=*/0x20,
                                             out_idx++, /*unlock=*/0) != 0) {
                sqlite3_finalize(utxo_ins_stmt);
                free(dels);
                nodus_witness_epoch_free(&es);
                return -1;
            }
        }
    }

    sqlite3_finalize(utxo_ins_stmt);
    free(dels);

    /* Reset per-epoch signed-block counters for the next epoch.
     * Deterministic: every node issues the same UPDATE at the same
     * boundary block, so all nodes enter the next epoch with counters
     * at 0. Counters are part of the validator merkle leaf — reset
     * MUST happen inside the same finalize_block transaction as the
     * settlement UTXO emits for the leaf hashes to match across nodes. */
    {
        char *reset_err = NULL;
        if (sqlite3_exec(w->db,
                          "UPDATE validators SET signed_blocks_this_epoch = 0 "
                          "WHERE signed_blocks_this_epoch > 0",
                          NULL, NULL, &reset_err) != SQLITE_OK) {
            fprintf(stderr,
                    "%s: epoch_settlement: reset counters failed: %s\n",
                    LOG_TAG, reset_err ? reset_err : "(null)");
            if (reset_err) sqlite3_free(reset_err);
            nodus_witness_epoch_free(&es);
            return -1;
        }
    }

    /* Burn aggregated dust + offline shares. */
    if (total_burned_here > 0) {
        (void)nodus_witness_supply_add_burned(w, total_burned_here, tx_hash);
    }

    nodus_witness_epoch_free(&es);
    /* Retire the settled epoch row. Design §3.1 — only the current
     * epoch carries a live row; previous-epoch snapshot is discarded. */
    nodus_witness_epoch_delete(w, settling_epoch_start);
    return 0;
}

/* Phase 9 / Task 48 — per-block attendance record.
 *
 * CORRECTED 2026-08-27. This used to say "for every PRECOMMIT voter …
 * update validator.last_signed_block". Both halves were wrong:
 *
 *   WHO  — exactly ONE row is credited, the BLOCK PROPOSER. The scan
 *          below compares each candidate's SHA3-512 digest against
 *          `proposer_id` (:3494) and `break`s on the first match
 *          (:3499); PRECOMMIT voters are never enumerated here.
 *   WHAT — TWO columns move, not one (:3546-3547):
 *            last_signed_block        = block_height
 *            signed_blocks_this_epoch = signed_blocks_this_epoch + 1
 *          and it is the SECOND one the epoch boundary actually reads
 *          (the liveness bar at :3255-3261). `last_signed_block` serves
 *          the monotonic guard at :3534 and nothing else in the
 *          settlement path.
 *
 * Rows are scanned with status IN (ACTIVE, RETIRING).
 *
 * voter_id is the first 32 bytes of SHA3-512(validator_pubkey) — the
 * same truncation the DHT identity layer uses (see
 * witness_setup_identity). We scan all rows with status in
 * {ACTIVE, RETIRING}, hash their pubkey, and match. A RETIRING
 * validator may still be on the committee for the current epoch so
 * we bump its last_signed_block too; only ACTIVE rows are considered
 * at the liveness check, however.
 *
 * DRIFT REPAIR (2026-07-31, landed with F1a below): this block used to
 * claim the function "opens its OWN short-lived SQLite transaction"
 * and that "one missed bump is tolerable". The C4 fix falsified both —
 * see the comment above the UPDATE: there is no BEGIN/COMMIT here, the
 * caller nodus_witness_commit_batch owns the outer transaction so the
 * counter bump is atomic with the block, and a non-zero return rolls
 * the whole block back precisely because a missed bump is NOT
 * tolerable — last_signed_block and
 * signed_blocks_this_epoch are both hashed into the validator leaf of
 * state_root (preimage nodus_witness_merkle.c:895-896, digested at
 * :1062-1065).
 *
 * Returns 0 on success, -1 on DB error. What that -1 MEANS differs by
 * caller, and the difference is not cosmetic:
 *
 *   nodus_witness_commit_batch (this file — grep the call, the line
 *     moves) — inside the outer block transaction. -1 there is a block
 *     REJECT: db_rollback runs and the block never lands. A GUARD.
 *
 *   sync replay (nodus_witness_sync.c:990) — the outer transaction is
 *     already CLOSED by then (replay_block → commit_batch → db_commit),
 *     so nothing here is atomic with the block and -1 cannot undo it.
 *     It aborts the sync session for an already-committed block. A
 *     DETECTOR, not a guard.
 *
 * Neither caller may report a -1 as success, but only the first can
 * prevent the divergence; the second can only stop syncing on top of it.
 */
int nodus_witness_record_attendance(nodus_witness_t *w,
                                      uint64_t block_height,
                                      const uint8_t *proposer_id) {
    if (!w || !w->db || !proposer_id || block_height == 0) return 0;

    /* Proposer-based attendance (2026-04-19 fix). The block's proposer_id
     * is part of the committed block header and is deterministic across
     * all nodes. Record attendance only for the proposer. Over a healthy
     * 7-member committee with round-robin leader election, each member
     * proposes roughly every 7 blocks. An offline proposer's
     * last_signed_block falls out of the settlement attendance window
     * (DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS) — its slot's pool share
     * is burned at epoch settlement. */
    sqlite3_stmt *sel = NULL;
    int rc = sqlite3_prepare_v2(w->db,
        "SELECT pubkey, last_signed_block FROM validators "
        "WHERE status IN (?, ?)",
        -1, &sel, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "%s: record_attendance: prepare select failed: %s\n",
                LOG_TAG, sqlite3_errmsg(w->db));
        return -1;
    }
    /* S3: ELIGIBLE is deliberately NOT in this filter. Attendance is
     * COMMITTEE-scoped — it credits the block's proposer, and only a
     * member of the epoch's active set can be elected proposer
     * (nodus_witness_bft_leader_index over the committee). RETIRING is
     * here because a RETIRING validator keeps its seat for the rest of
     * the epoch. At an epoch-boundary block the ordering also works out:
     * commit_batch calls record_attendance BEFORE finalize_block, so
     * this scan still sees the ENDING epoch's statuses, which is the
     * epoch the proposer actually served. */
    sqlite3_bind_int(sel, 1, (int)DNAC_VALIDATOR_ACTIVE);
    sqlite3_bind_int(sel, 2, (int)DNAC_VALIDATOR_RETIRING);

    uint8_t match_pubkey[DNAC_PUBKEY_SIZE];
    uint64_t match_last_signed = 0;
    bool matched = false;

    while ((rc = sqlite3_step(sel)) == SQLITE_ROW) {
        const void *pk = sqlite3_column_blob(sel, 0);
        int pk_len = sqlite3_column_bytes(sel, 0);
        if (!pk || pk_len != DNAC_PUBKEY_SIZE) continue;

        uint8_t digest[64];
        qgp_sha3_512(pk, DNAC_PUBKEY_SIZE, digest);
        if (memcmp(digest, proposer_id, NODUS_T3_WITNESS_ID_LEN) != 0)
            continue;

        memcpy(match_pubkey, pk, DNAC_PUBKEY_SIZE);
        match_last_signed = (uint64_t)sqlite3_column_int64(sel, 1);
        matched = true;
        break;
    }
    sqlite3_finalize(sel);

    /* F1a — the scan's step result decides whether "no match" is a FACT
     * or a DB failure wearing its clothes. A mid-scan SQLITE_IOERR /
     * SQLITE_BUSY / SQLITE_CORRUPT used to leave the loop with
     * matched == false, which the line below reads as the legitimate
     * "proposer is not a validator" outcome: this function returned 0,
     * commit_batch's rollback never fired, and last_signed_block /
     * signed_blocks_this_epoch stayed put on THIS node while every peer
     * advanced them. Both columns are hashed into the validator leaf
     * (preimage nodus_witness_merkle.c:895-896, digested at :1062-1065),
     * so the miss is a permanently divergent validator_root →
     * state_root. Same fork mechanism the C4 comment below documents —
     * C4 hardened the WRITE, this hardens the READ that decides
     * whether to write.
     *
     * GUARDED ON !matched, and that is the whole subtlety: the loop
     * BREAKS on a hit, so on the success path rc == SQLITE_ROW, not
     * SQLITE_DONE. A bare `rc != SQLITE_DONE` here would reject every
     * honest block on every node. !matched is exactly "the loop was not
     * terminated by our own break", and only then is rc the scan's
     * terminal code, where SQLITE_DONE means genuine exhaustion and
     * anything else means the walk died early. */
    if (!matched && rc != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG,
            "record_attendance: validator scan step failed rc=%d at block "
            "%llu — cannot tell 'not a validator' from a DB failure, "
            "rejecting", rc, (unsigned long long)block_height);
        return -1;
    }

    if (!matched) return 0;  /* proposer not a known validator — skip */
    if (block_height <= match_last_signed) return 0;  /* monotonic */

    /* C4 fix: no BEGIN/COMMIT here — caller (commit_batch) owns the outer
     * transaction so this UPDATE is atomic with the block's finalize_block.
     * Without this, SQLITE_BUSY on a single witness would silently roll
     * back the counter bump while other witnesses succeed, producing
     * different signed_blocks_this_epoch values in the validator_root
     * feeding the NEXT block's state_root → chain fork under no Byzantine
     * actor. */
    sqlite3_stmt *upd = NULL;
    rc = sqlite3_prepare_v2(w->db,
        "UPDATE validators SET "
        "  last_signed_block = ?,"
        "  signed_blocks_this_epoch = signed_blocks_this_epoch + 1 "
        "WHERE pubkey = ?",
        -1, &upd, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_int64(upd, 1, (int64_t)block_height);
    sqlite3_bind_blob(upd, 2, match_pubkey, DNAC_PUBKEY_SIZE, SQLITE_STATIC);
    int urc = sqlite3_step(upd);
    sqlite3_finalize(upd);
    if (urc != SQLITE_DONE) return -1;

    QGP_LOG_DEBUG(LOG_TAG,
        "record_attendance: block %llu — proposer credited",
        (unsigned long long)block_height);
    return 0;
}

/* finalize_block — Phase 3 / Task 3.2.
 *
 * Per-block work: invalidate the cached state_root, recompute it from
 * the post-batch UTXO set, run the supply invariant check once, build
 * the tx_root over the batch's TX hashes, and write the block row.
 *
 * MUST be called inside the same outer DB transaction as the
 * apply_tx_to_state calls that produced the batch. The state_root
 * read sees the uncommitted UTXO writes from that transaction.
 *
 * tx_hashes is the flat n*64 buffer of raw TX hashes for tx_root
 * computation. tx_count is the batch size (1..NODUS_W_MAX_BLOCK_TXS).
 *
 * The supply invariant check is currently advisory (logs only) to
 * preserve legacy single-TX behavior. Phase 6 commit_batch wrapper
 * promotes a violation to fatal via outer rollback.
 */
/* Non-static — see apply_tx_to_state comment. */
int finalize_block(nodus_witness_t *w,
                    const uint8_t *tx_hashes,
                    uint32_t tx_count,
                    const uint8_t *proposer_id,
                    uint64_t timestamp,
                    uint64_t expected_height,
                    const uint8_t *chain_def_blob,
                    size_t chain_def_blob_len,
                    const uint8_t *expected_state_root) {
    if (!w || !w->db) return -1;
    if (!proposer_id) return 0;  /* legacy: skip block_add when no proposer */
    if (tx_count == 0 || tx_count > NODUS_W_MAX_BLOCK_TXS) return -1;
    if (!tx_hashes) return -1;

    /* Phase 9 / Task 47 — finalize_block MUST run inside the outer
     * single-transaction block wrapper. The commit_genesis /
     * commit_batch / replay_block callers open BEGIN IMMEDIATE before
     * the first apply_tx_to_state and either COMMIT on success or
     * ROLLBACK on any error (design F-STATE-02). Catch callers that
     * bypass the wrapper here — they would silently partial-commit. */
    if (!w->in_block_transaction) {
        fprintf(stderr, "%s: finalize_block: called outside block "
                "transaction (F-STATE-02 violation)\n", LOG_TAG);
        return -1;
    }

    /* Phase 8 Task 46 — epoch-boundary state transitions.
     *
     * MUST run AFTER per-TX apply_tx_to_state calls (so pending-commission
     * rows set by this block's VALIDATOR_UPDATE TXs with
     * pending_effective_block == block_height are visible) and BEFORE the
     * state_root recomputation below (so all epoch-driven mutations are
     * reflected in the committed root). This implements step 5 of design
     * §4.1's block-commit order.
     *
     * `expected_height` is the height the block is being committed at —
     * passed by all callers (commit_genesis, commit_batch, replay_block).
     */
    if (apply_epoch_boundary_transitions(w, expected_height) != 0) {
        fprintf(stderr, "%s: finalize_block: epoch_boundary failed\n",
                LOG_TAG);
        return -1;
    }

    /* S3 — genesis validator-set snapshots (no-op at every other height).
     *
     * PLACED HERE, not in nodus_witness_commit_genesis, on purpose:
     * finalize_block is the single point BOTH genesis paths pass through.
     * The BFT-original genesis and the sync replay of genesis both call
     * nodus_witness_commit_genesis (handle_commit in this file, and
     * nodus_witness_sync.c:910-916 which dispatches a lone GENESIS tx to
     * the same wrapper), and that wrapper's only block-writing step is
     * this finalize_block call. Hooking the wrapper instead would have
     * been equivalent today but fragile: the sync.c:975-1005 comment
     * records the class of bug where a step lands on one commit path and
     * not the other, and the two DBs then differ forever.
     *
     * Ordering inside the transaction: genesis validator seeding
     * (nodus_witness_genesis_seed_validators) and the genesis_state /
     * supply_tracking writes all happen BEFORE this call, so the builder
     * sees the seeded validators. The block row itself is written at the
     * end of this function, which is fine — the snapshot builder reads
     * validators, not blocks (its bootstrap tiebreak deliberately falls
     * back to the all-zero seed; see nodus_witness_vset_commit_genesis).
     *
     * The genesis condition is height 1 AND a chain_def payload: both
     * real genesis paths (BFT-original and sync replay) reach this call
     * through nodus_witness_commit_genesis, which is the ONLY caller
     * that passes a non-NULL chain_def_blob (bft.c commit_genesis;
     * commit_batch always passes NULL). Height alone would be wrong —
     * unit fixtures legitimately finalize ordinary txs at height 1
     * against an unseeded validators table, and a real chain's height-1
     * block without a chain_def does not exist on any live path (Rule P
     * has required the chain_def since Task 56; the legacy no-chain_def
     * archive chains are dead and never replay through here). */
    if (chain_def_blob != NULL &&
        nodus_witness_vset_commit_genesis(w, expected_height) != 0) {
        fprintf(stderr, "%s: finalize_block: genesis validator-set "
                "snapshot failed\n", LOG_TAG);
        return -1;
    }

    /* v0.16 stage C.2 — per-block inflation emission.
     *
     * Every block height mints nodus_emission_per_block(bh) raw DNAC
     * (see nodus_witness_emission.h for the 32→16→8→4→2→1 schedule).
     * The mint accrues into:
     *   (a) supply_tracking.total_minted — bumps current_supply too.
     *   (b) epoch_state.epoch_pool_accum — Stage E's
     *       apply_epoch_settlement drains this into UTXOs.
     *
     * Hard-Fork v1: the INFLATION_START_BLOCK override (chain_config)
     * gates activation. Pre-wipe chains passed 0 (=disabled) here;
     * v0.16 chains default to 1 (active from block 1).
     *
     * O15J Block 2 (A2) — this comment used to say "an unfetchable
     * override is treated as 1ULL so that a transient DB fault cannot
     * silently turn off emission cross-nodes". That was the fail-open,
     * described as if it were the fix: substituting 1ULL only covers the
     * case where the override would DELAY emission, and does nothing when
     * the real override is EARLIER than 1 or when peers read a later
     * start. Either way the node mints on a schedule it cannot prove its
     * peers share, and total_minted feeds the supply gate and the
     * epoch_state leaves of state_root. The read is three-valued now:
     * genuinely no row still means 1ULL, an unreadable row fails the
     * block.
     */
    {
        uint64_t inflation_start = 0;
        int cfg_rc = nodus_chain_config_get_u64(w,
                                        DNAC_CFG_INFLATION_START_BLOCK,
                                        expected_height,
                                        1ULL,
                                        &inflation_start);
        if (cfg_rc < 0) {
            QGP_LOG_ERROR(LOG_TAG, "finalize_block: INFLATION_START_BLOCK "
                          "unreadable at height %llu — refusing to mint on "
                          "a guessed emission schedule",
                          (unsigned long long)expected_height);
            return -1;
        }
        uint64_t emission = 0;
        if (inflation_start != 0 && expected_height >= inflation_start) {
            emission = nodus_emission_per_block(expected_height);
        }

        if (emission > 0) {
            /* Global supply counters. */
            if (nodus_witness_supply_add_minted(w, emission) != 0) {
                fprintf(stderr, "%s: finalize_block: supply_add_minted failed\n",
                        LOG_TAG);
                return -1;
            }

            /* Per-epoch pool accumulator. Canonical epoch_start_height
             * formula: floor(block_height / DNAC_EPOCH_LENGTH) *
             * DNAC_EPOCH_LENGTH. Auto-seed the row on first touch per
             * epoch; Stage D.1 will layer snapshot_hash + snapshot_blob
             * on top of it at the first block of each new epoch. */
            uint64_t epoch_start = (expected_height / (uint64_t)DNAC_EPOCH_LENGTH) *
                                   (uint64_t)DNAC_EPOCH_LENGTH;
            int add_rc = nodus_witness_epoch_add_pool(w, epoch_start, emission);
            if (add_rc == 1) {
                /* Row missing — seed with zeroed snapshot_hash and the
                 * current mint as the starting pool. Stage D.1
                 * overwrites snapshot_hash at epoch-start. */
                nodus_epoch_state_t seed = {0};
                seed.epoch_start_height = epoch_start;
                seed.epoch_pool_accum   = emission;
                int ins_rc = nodus_witness_epoch_insert(w, &seed);
                if (ins_rc != 0 && ins_rc != -2) {
                    fprintf(stderr,
                        "%s: finalize_block: epoch_insert seed failed rc=%d\n",
                        LOG_TAG, ins_rc);
                    return -1;
                }
                /* If -2 (another path raced us), retry add_pool. */
                if (ins_rc == -2) {
                    if (nodus_witness_epoch_add_pool(w, epoch_start, emission)
                        != 0) {
                        fprintf(stderr,
                            "%s: finalize_block: epoch_add_pool retry failed\n",
                            LOG_TAG);
                        return -1;
                    }
                }

                /* Stage D.1: first time an epoch_state row is seeded,
                 * capture the committee + delegation snapshot for
                 * this epoch. Idempotent — a retry with the same
                 * state produces the same snapshot_hash. */
                if (nodus_witness_epoch_snapshot_apply(w, epoch_start) != 0) {
                    fprintf(stderr,
                        "%s: finalize_block: epoch_snapshot_apply failed\n",
                        LOG_TAG);
                    return -1;
                }
            } else if (add_rc != 0) {
                fprintf(stderr,
                    "%s: finalize_block: epoch_add_pool failed rc=%d\n",
                    LOG_TAG, add_rc);
                return -1;
            }
        }
    }

    /* Stage E — epoch settlement trigger.
     *
     * Fires strictly on block_height % DNAC_EPOCH_LENGTH == 0 &&
     * block_height > 0 (RT-C1: no round/view dependency). Drains the
     * prior epoch's epoch_pool_accum into UTXOs per the Stage E
     * distribution rules and retires that epoch_state row. The NEW
     * epoch's row was already auto-seeded by the C.2 path above, so
     * compute_state_root below sees the updated table (settled row
     * gone, new row present). */
    if (expected_height > 0 &&
        (expected_height % (uint64_t)DNAC_EPOCH_LENGTH) == 0) {
        uint64_t settling_epoch_start =
            expected_height - (uint64_t)DNAC_EPOCH_LENGTH;
        if (apply_epoch_settlement(w, settling_epoch_start) != 0) {
            fprintf(stderr,
                "%s: finalize_block: epoch_settlement failed (epoch_start=%llu)\n",
                LOG_TAG, (unsigned long long)settling_epoch_start);
            return -1;
        }
    }

    /* Invalidate the cached UTXO checksum — the per-TX writes from this
     * batch made the previous root stale. Phase 11 renames this to
     * cached_state_root. */
    w->cached_state_root_valid = false;

    /* 1. Compute post-batch state_root.
     *
     * Phase 3 / Task 10: extended to SHA3-512(utxo || validator ||
     * delegation || reward) via nodus_witness_merkle_compute_state_root.
     * validator/delegation/reward subtrees default to empty-root stubs
     * until Phase 4+ populates them from real state. */
    uint8_t state_root[NODUS_T3_TX_HASH_LEN];
    if (nodus_witness_merkle_compute_state_root(w, state_root) != 0) {
        fprintf(stderr, "%s: finalize_block: state_root compute failed\n",
                LOG_TAG);
        return -1;
    }

    /* C3 fix — HALT on state_root divergence from the leader's claim.
     *
     * expected_state_root == NULL: genesis, or the leader's own commit
     * path (we are the state_root oracle). Non-NULL: follower replay
     * from a COMMIT / sync_rsp — must match byte-for-byte or the
     * block does not persist, the outer txn rolls back, and we enter
     * safety halt. This replaces the former WARN-only divergence log
     * which silently accepted the block's certs against a state this
     * node did not actually have. */
    if (expected_state_root &&
        memcmp(state_root, expected_state_root, NODUS_T3_TX_HASH_LEN) != 0) {
        char local_hex[17], leader_hex[17];
        for (int i = 0; i < 8; i++) {
            snprintf(local_hex + i * 2, sizeof(local_hex) - i * 2,
                     "%02x", state_root[i]);
            snprintf(leader_hex + i * 2, sizeof(leader_hex) - i * 2,
                     "%02x", expected_state_root[i]);
        }
        fprintf(stderr,
            "%s: FATAL: state_root DIVERGED at h=%llu — local=%s... "
            "leader=%s... — entering safety halt\n",
            LOG_TAG, (unsigned long long)expected_height,
            local_hex, leader_hex);
        w->safety_halt = true;
        w->halt_block_height = expected_height;
        w->halt_timestamp = (uint64_t)time(NULL);
        /* 2026-05-02 audit B-3 + C-4: capture historical committee
         * snapshot AT halt height so halt_recovery_check (Faz 4D-E)
         * can tally disagree-quorum against pinned membership rather
         * than current gossip roster. Phantom committee members
         * spawned during halt window cannot influence the vote.
         * Failure to capture (DB error, etc) leaves halt_committee_
         * count = 0 → halt_recovery_check treats as inconclusive. */
        nodus_committee_member_t *halt_cm = NULL;
        int halt_cm_count = 0;
        if (nodus_committee_get_for_block_alloc(w, expected_height, &halt_cm,
                                                  &halt_cm_count) == 0) {
            if (halt_cm_count > DNAC_MAX_ACTIVE_VALIDATORS)
                halt_cm_count = DNAC_MAX_ACTIVE_VALIDATORS;
            w->halt_committee_count = halt_cm_count;
            for (int i = 0; i < halt_cm_count; i++) {
                memcpy(w->halt_committee_pubkeys[i], halt_cm[i].pubkey,
                       DNAC_PUBKEY_SIZE);
            }
            free(halt_cm);
        } else {
            free(halt_cm);
            w->halt_committee_count = 0;
            fprintf(stderr,
                "%s: halt committee snapshot failed at h=%llu — "
                "halt_recovery_check will treat as inconclusive\n",
                LOG_TAG, (unsigned long long)expected_height);
        }
        /* 2026-05-02 audit M-4: reset round phase to IDLE so the
         * subsequent halt_recovery_check / sync_check tick (Faz 4D-E)
         * is not gated by the IDLE guard at sync.c:165. Without this
         * reset, a halt latched mid-PRECOMMIT (US-1's actual case at
         * 11:14:47) leaves phase=PREVOTE/PRECOMMIT until view-change
         * timeout, silently blocking auto-recovery. */
        w->round_state.phase = NODUS_W_PHASE_IDLE;
        return -1;
    }

    /* 2. Supply invariant — v0.16 Stage F.1 HARD gate.
     *
     * expected = genesis_supply + total_minted − total_burned
     * observed = Σ utxo_native + Σ self_stake + Σ total_delegated
     *          + Σ epoch_state.epoch_pool_accum
     *
     * Any mismatch rejects the block so the outer commit_batch
     * transaction rolls back — no state_root, no block row, no
     * UTXO mutations reach the committed DB. The legacy advisory
     * check (supply_invariant_violated) is retained below for the
     * attribution-replay path, which runs per-TX diagnostics when a
     * batch fails. */
    if (check_supply_invariant_v016(w) != 0) {
        fprintf(stderr,
            "%s: finalize_block REJECTED: supply invariant violated at h=%llu\n",
            LOG_TAG, (unsigned long long)expected_height);
        return -1;
    }
    (void)supply_invariant_violated(w);

    /* 3. tx_root via RFC 6962 over the batch's TX hashes (Phase 2 wrapper). */
    uint8_t tx_root[NODUS_T3_TX_HASH_LEN];
    if (nodus_witness_merkle_tx_root(tx_hashes, (size_t)tx_count, tx_root) != 0) {
        fprintf(stderr, "%s: finalize_block: tx_root compute failed\n",
                LOG_TAG);
        return -1;
    }

    /* 4. Block row insert. */
    if (nodus_witness_block_add(w, tx_root, tx_count, timestamp,
                                  proposer_id, state_root,
                                  chain_def_blob, chain_def_blob_len) != 0) {
        fprintf(stderr, "%s: finalize_block: block_add failed\n", LOG_TAG);
        return -1;
    }

    return 0;
}

/* v0.16 stage A.5: nodus_witness_get_block_fee_pool accessor removed
 * with the block_fee_pool field itself. Stage C.3 replaces the
 * concept with total_burned (fees) and epoch_pool_accum (mint). */

/* nodus_witness_commit_block — DELETED in Phase 11 partial.
 *
 * The thin dispatcher had a single remaining caller (sync.c:521); that
 * caller now calls nodus_witness_commit_genesis or
 * nodus_witness_replay_block directly. The legacy single-TX commit
 * wrapper / Phase 7 dispatcher is fully gone. */

/* ════════════════════════════════════════════════════════════════════
 * Phase 7 / Task 7.4 — legacy single-TX nodus_witness_bft_start_round
 * DELETED. Genesis and forwarded-genesis callers now build a 1-entry
 * mempool entry array and call nodus_witness_bft_start_round_from_entries
 * instead. Phase 7 / Task 7.6 made the commit path multi-tx-aware so
 * batch-of-1 genesis works (commit_genesis dispatches the chain DB
 * bootstrap when w->db is still NULL).
 * ════════════════════════════════════════════════════════════════════ */

/* ════════════════════════════════════════════════════════════════════
 * Phase 7 / Task 7.3 — shared start-round body (leader only)
 *
 * The body of the previous public bft_start_round_batch. Both
 * from_entries and from_mempool funnel here. Stays file-static; tests
 * exercise it through the wrappers.
 * ════════════════════════════════════════════════════════════════════ */

static int bft_start_round_internal(nodus_witness_t *w,
                                      nodus_witness_mempool_entry_t **entries,
                                      int count) {
    if (!w || !entries || count <= 0) return -1;

    /* F17 A2 — transport-layer roster swap (gossip discovery). Consensus
     * authority is NOT tied to this swap anymore; bft_config is refreshed
     * from committee just below. */
    if (w->pending_roster_ready &&
        w->pending_roster.n_witnesses != w->roster.n_witnesses) {
        memcpy(&w->roster, &w->pending_roster, sizeof(nodus_witness_roster_t));
        w->pending_roster_ready = false;
        fprintf(stderr, "%s: force roster swap before batch: %u witnesses "
                "(transport)\n", LOG_TAG, w->roster.n_witnesses);
    }

    /* F17 A2 — recompute BFT config from the chain-derived committee
     * for the next block. This is the authoritative quorum source. */
    /* O15O Faz 1 — a fault here would set the round's QUORUM from the
     * committee at height 1. Abort the round start: no state has been
     * mutated yet at this point, so returning is a clean no-op and the
     * leader simply produces no proposal this tick. */
    uint64_t start_tip = 0;
    if (nodus_witness_block_height_checked(w, &start_tip) != 0) {
        fprintf(stderr, "%s: start_round — chain-height read faulted; "
                "refusing to open a round against an unknown tip\n",
                LOG_TAG);
        return -1;
    }
    uint64_t next_bh = start_tip + 1;
    /* O15J Faz 3 — the terminal-height refusal (a committed ACTIVE
     * activation record ending the legacy chain at H_act) is deleted with
     * the ceremony: no chain is terminal any more, because none is
     * scheduled to hand over to a successor. */
    /* O15D/O15F — a SUCCESSOR round carries V2 ENVELOPE (200) and CLAIM
     * (201) entries and nothing else: a legacy-typed entry (genesis
     * included) can never open a round on a successor chain. Content
     * authority stays byte-driven (the wire-family marker, checked at
     * classification/admission); this is the round-entry backstop. */
    if (w->v2_successor) {
        for (int sce = 0; sce < count; sce++) {
            if (!entries[sce] ||
                (entries[sce]->tx_type != NODUS_W_TX_V2_ENVELOPE &&
                 entries[sce]->tx_type != NODUS_W_TX_V2_CLAIM)) {
                fprintf(stderr, "%s: successor chain — legacy entry "
                        "refused at round start (idx %d)\n", LOG_TAG, sce);
                return -1;
            }
        }
    }

    if (refresh_bft_config_from_committee(w, next_bh) != 0) {
        fprintf(stderr, "%s: failed to load committee for block %llu\n",
                LOG_TAG, (unsigned long long)next_bh);
        return -1;
    }

    if (!nodus_witness_bft_consensus_active(w)) {
        fprintf(stderr, "%s: consensus disabled (committee_count=%u < %d)\n",
                LOG_TAG, w->bft_config.n_witnesses, NODUS_T3_MIN_WITNESSES);
        return -1;
    }

    if (!nodus_witness_bft_is_leader(w)) {
        fprintf(stderr, "%s: batch start_round but not leader\n", LOG_TAG);
        return -1;
    }

    if (w->round_state.phase != NODUS_W_PHASE_IDLE) {
        fprintf(stderr, "%s: batch round rejected — round active (phase=%d)\n",
                LOG_TAG, w->round_state.phase);
        return -1;
    }

    /* Compute block_hash = SHA3-512(tx_hash_1 || tx_hash_2 || ... || tx_hash_n) */
    uint8_t block_hash[NODUS_T3_TX_HASH_LEN];
    {
        uint8_t hash_input[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_TX_HASH_LEN];
        size_t total_len = 0;
        for (int i = 0; i < count; i++) {
            memcpy(hash_input + total_len, entries[i]->tx_hash,
                   NODUS_T3_TX_HASH_LEN);
            total_len += NODUS_T3_TX_HASH_LEN;
        }
        nodus_key_t bh;
        if (nodus_hash(hash_input, total_len, &bh) != 0) {
            fprintf(stderr, "%s: block_hash computation failed\n", LOG_TAG);
            return -1;
        }
        memcpy(block_hash, bh.bytes, NODUS_T3_TX_HASH_LEN);
    }

    /* O15O Faz 1 — THE ROUND ANCHOR, read BEFORE any round state is
     * touched. Every cert_sig preimage in this round is signed over
     * round_state.block_height, so a fault answering 0 would anchor the
     * round at height 1 and make this leader sign a PREPARED preimage no
     * follower can reproduce. Read it here, ahead of the increment and
     * the memset below, so a fault leaves ROUND state untouched:
     * current_round is unchanged and the previous round's state is left
     * exactly as it was for the next tick to re-enter on.
     *
     * ⚠ SAID EXACTLY, because an earlier draft of this comment said "with
     * NOTHING mutated" and that was FALSE. By the time control reaches
     * here two things have already been written, and both survive this
     * return: the F17 A2 transport-roster force-swap (:4400-4405) and
     * `w->bft_config`, rewritten by refresh_bft_config_from_committee at
     * :4443. That residue is identical to what every pre-existing `return
     * -1` in this window already leaves (:4438, :4446, :4452, :4457,
     * :4463), so this fault path is no worse than its neighbours — but
     * "nothing" was a claim the code contradicts, and the distinction
     * matters to anyone reasoning about what a failed start_round leaves
     * behind. Node-local transport/config state: yes. Round or view
     * state: no. */
    uint64_t anchor_tip = 0;
    if (nodus_witness_block_height_checked(w, &anchor_tip) != 0) {
        fprintf(stderr, "%s: start_round — chain-height read faulted while "
                "anchoring the round; aborting rather than signing a "
                "PREPARED preimage at height 1\n", LOG_TAG);
        return -1;
    }

    /* Initialize round state */
    w->current_round++;
    round_state_free_batch(&w->round_state);
    memset(&w->round_state, 0, sizeof(w->round_state));

    w->round_state.round = w->current_round;
    w->round_state.view = w->current_view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    /* A2 fix — anchor the proposed-block height at round start. All
     * cert_sig signing/verification within this round reads from
     * round_state.block_height, not from a fresh
     * nodus_witness_block_height(w)+1 lookup, so leader and followers
     * agree on the round's height even when local heights have drifted. */
    w->round_state.block_height = anchor_tip + 1;
    memcpy(w->round_state.tx_root, block_hash, NODUS_T3_TX_HASH_LEN);
    memcpy(w->round_state.tx_hash, block_hash, NODUS_T3_TX_HASH_LEN);
    w->round_state.proposal_timestamp = (uint64_t)time(NULL);
    memcpy(w->round_state.proposer_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    w->round_state.phase_start_time = time_ms();
    O15H_DIAG(w, "round_start_leader", w->my_id, w->round_state.block_height,
              w->current_view, w->view_change_target, w->round_state.phase,
              w->round_state.phase_start_time, 0, "PROPOSE", 1,
              0, w->bft_config.quorum, "leader opened a round");

    /* Store batch entries. Genesis is single-TX but flows through the same
     * batch path since 4d8ad851; propagate the entry's actual tx_type so the
     * quorum check at handle_vote() can apply the GENESIS unanimous rule. */
    w->round_state.tx_type = (count > 0) ? entries[0]->tx_type : NODUS_W_TX_SPEND;
    w->round_state.batch_count = count;
    for (int i = 0; i < count; i++)
        w->round_state.batch_entries[i] = entries[i];

    /* Record our own PREVOTE */
    memcpy(w->round_state.prevotes[0].voter_id, w->my_id,
           NODUS_T3_WITNESS_ID_LEN);
    /* F17 A1 — carry our pubkey alongside for committee authorization. */
    memcpy(w->round_state.prevotes[0].pubkey,
           w->server->identity.pk.bytes, DNAC_PUBKEY_SIZE);
    w->round_state.prevotes[0].vote = NODUS_W_VOTE_APPROVE;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count = 1;

    /* C5 — sign PREPARED preimage (view, block_height, tx_hash). Attached
     * to our self-recorded prevotes[0].signature AND to the outgoing
     * PREVOTE's cert_sig so receivers can verify and the PREVOTE-quorum
     * hook can assemble w->last_prepared. Failure aborts the round —
     * view-change timeout kicks liveness via new leader.
     * A2 fix — height comes from round_state (set just above) so leader
     * and followers sign over the same anchor. */
    uint8_t prep_preimage[NODUS_WITNESS_PREPARED_PREIMAGE_LEN];
    uint64_t prep_height = w->round_state.block_height;
    if (compute_prepared_preimage(w->current_view, prep_height, block_hash,
                                    w->chain_id, prep_preimage) != 0) {
        fprintf(stderr, "%s: prepared preimage compute failed — "
                "aborting round\n", LOG_TAG);
        return -1;
    }
    nodus_sig_t prep_sig;
    if (nodus_sign_prepared_vote(&prep_sig, prep_preimage,
                                   sizeof(prep_preimage),
                                   &w->server->identity.sk) != 0) {
        fprintf(stderr, "%s: prepared vote sign failed — aborting round\n",
                LOG_TAG);
        return -1;
    }
    memcpy(w->round_state.prevotes[0].signature, prep_sig.bytes,
           NODUS_SIG_BYTES);

    /* Build batch PROPOSAL */
    nodus_t3_msg_t proposal;
    memset(&proposal, 0, sizeof(proposal));
    proposal.type = NODUS_T3_PROPOSE;
    proposal.txn_id = ++w->next_txn_id;

    proposal.propose.batch_count = count;
    memcpy(proposal.propose.tx_root, block_hash, NODUS_T3_TX_HASH_LEN);
    /* A2 fix — broadcast our claimed proposed-block height so all
     * receivers anchor their PREPARED-preimage signing/verification on
     * the same value. Followers re-validate (height == local + 1) before
     * trusting it; the leader cannot force followers off-chain via this
     * field, only assert "I am proposing block H." */
    proposal.propose.block_height = w->round_state.block_height;

    for (int i = 0; i < count; i++) {
        nodus_t3_batch_tx_t *btx = &proposal.propose.batch_txs[i];
        nodus_witness_mempool_entry_t *e = entries[i];
        memcpy(btx->tx_hash, e->tx_hash, NODUS_T3_TX_HASH_LEN);
        btx->nullifier_count = e->nullifier_count;
        for (int j = 0; j < e->nullifier_count; j++)
            btx->nullifiers[j] = e->nullifiers[j];
        btx->tx_type = e->tx_type;
        btx->tx_data = e->tx_data;
        btx->tx_len = e->tx_len;
        btx->client_pubkey = e->client_pubkey;
        btx->client_sig = e->client_sig;
        btx->fee = e->fee;
    }

    int sent = nodus_witness_bft_broadcast(w, &proposal);

    /* Broadcast own PREVOTE */
    nodus_t3_msg_t prevote;
    memset(&prevote, 0, sizeof(prevote));
    prevote.type = NODUS_T3_PREVOTE;
    prevote.txn_id = ++w->next_txn_id;
    memcpy(prevote.vote.vote_target, block_hash, NODUS_T3_TX_HASH_LEN);
    prevote.vote.vote = NODUS_W_VOTE_APPROVE;
    memcpy(prevote.vote.cert_sig, prep_sig.bytes, NODUS_SIG_BYTES);
    nodus_witness_bft_broadcast(w, &prevote);

    fprintf(stderr, "%s: batch proposal broadcast to %d peers "
            "(round %lu, %d TXs, block_hash=%.16s...)\n",
            LOG_TAG, sent, (unsigned long)w->current_round, count,
            "computed");

    /* O15C-C D2 — votes that raced ahead of our own round start. */
    nodus_witness_bft_drain_vote_buffer(w);

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Phase 7 / Task 7.1 — start round from caller-owned entries
 *
 * Thin pass-through to bft_start_round_batch. In commit 3 of the Phase 7
 * refactor bft_start_round_batch becomes a static bft_start_round_internal
 * and both from_entries and from_mempool become the only public entry
 * points. For now the wrapper exists so genesis callers can migrate to
 * the entry-based API without touching the underlying body.
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_start_round_from_entries(nodus_witness_t *w,
                                                 nodus_witness_mempool_entry_t **entries,
                                                 int count) {
    QGP_BENCH_START(QGP_BENCH_BFT_ROUND);
    int _rc = bft_start_round_internal(w, entries, count);
    QGP_BENCH_END(QGP_BENCH_BFT_ROUND);
    return _rc;
}

/* ════════════════════════════════════════════════════════════════════
 * Phase 7 / Task 7.2 — start round from mempool
 *
 * Pops a batch from the mempool, runs Phase 4 layer-2 chained-UTXO
 * filtering and DB-nullifier rechecks, then forwards the surviving
 * entries to bft_start_round_batch. On round-start failure, surviving
 * entries are returned to the mempool so they can be retried in the
 * next block interval; entries dropped by the validation pass are
 * freed.
 *
 * Body lifted verbatim (semantically) from the previous static
 * nodus_witness_propose_batch in nodus_witness.c. The helpers
 * nodus_compute_output_nullifier and nodus_extract_output_nullifiers
 * moved with it — they are static-local to bft.c now.
 * ════════════════════════════════════════════════════════════════════ */

/* Static helper — DNAC nullifier mirror.
 *
 * Mirrors dnac_derive_nullifier so nodus does not link libdnac —
 * duplication is acceptable for a 15-line crypto-only function. If the
 * DNAC nullifier scheme ever gains a secret input, this helper becomes
 * silently impotent and the entire 3-layer chained-UTXO defense MUST
 * be redesigned. */
static int nodus_compute_output_nullifier(const char *owner_fp,
                                            const uint8_t *seed,
                                            uint8_t *out64) {
    if (!owner_fp || !seed || !out64) return -1;
    uint8_t buf[256];
    size_t off = 0;
    size_t fp_len = strlen(owner_fp);
    if (fp_len > 192) fp_len = 192;
    memcpy(buf, owner_fp, fp_len); off = fp_len;
    memcpy(buf + off, seed, 32); off += 32;
    return qgp_sha3_512(buf, off, out64);
}

/* Walk a serialized TX's outputs and append each output's future
 * nullifier to a flat 64-byte array. Returns the number of outputs
 * appended (0 on parse failure). */
static int nodus_extract_output_nullifiers(const uint8_t *tx_data, uint32_t tx_len,
                                             uint8_t out_nullifiers[][64],
                                             int max_outputs) {
    if (!tx_data || tx_len < DNAC_TX_HEADER_SIZE + 1 || !out_nullifiers || max_outputs <= 0) return 0;
    size_t off = DNAC_TX_HEADER_SIZE;  /* v0.17.1: +committed_fee → 82 */
    if (off >= tx_len) return 0;
    uint8_t in_count = tx_data[off++];
    off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);
    if (off >= tx_len) return 0;
    uint8_t out_count = tx_data[off++];

    int written = 0;
    for (int i = 0; i < out_count && off + 235 <= tx_len && written < max_outputs; i++) {
        off += 1;   /* version */
        const char *owner_fp = (const char *)(tx_data + off);
        char fp_buf[129];
        memcpy(fp_buf, owner_fp, 128);
        fp_buf[128] = '\0';
        off += 129; /* fingerprint */
        off += 8;   /* amount */
        off += 64;  /* token_id */
        const uint8_t *seed = tx_data + off;
        off += 32;  /* seed */
        if (off >= tx_len) break;
        uint8_t ml = tx_data[off++]; /* memo_len */
        off += ml;

        if (nodus_compute_output_nullifier(fp_buf, seed, out_nullifiers[written]) == 0) {
            written++;
        }
    }
    return written;
}

/* Requeue batch[from, to) into the mempool and NULL the slots. A full or
 * duplicate-rejecting mempool cannot keep the entry, so it is freed
 * rather than leaked — the same disposal the Q7 isolation path above
 * already uses. */
static void shape_requeue(nodus_witness_t *w,
                          nodus_witness_mempool_entry_t **batch,
                          int from, int to) {
    for (int i = from; i < to; i++) {
        if (!batch[i]) continue;
        if (nodus_witness_mempool_add(&w->mempool, batch[i]) != 0)
            nodus_witness_mempool_entry_free(batch[i]);
        batch[i] = NULL;
    }
}

/* Destroy batch[idx] and close the gap; *valid shrinks by one. Used ONLY
 * where the entry is known to be permanently unusable — a client that
 * loses its receipt this way must resubmit. */
static void shape_drop(nodus_witness_mempool_entry_t **batch, int idx,
                       int *valid) {
    nodus_witness_mempool_entry_free(batch[idx]);
    for (int i = idx; i < *valid - 1; i++)
        batch[i] = batch[i + 1];
    batch[*valid - 1] = NULL;
    (*valid)--;
}

/*
 * O15D / capacity season — SUCCESSOR batch SHAPING.
 *
 * Bring a popped batch down to something the commit engine will accept,
 * DESTROYING only what is permanently invalid and REQUEUEING everything
 * that is merely surplus. Returns the number of entries at the head of
 * `batch` that are proposable (they stay owned by the caller); every
 * other slot is NULLed after being requeued or freed.
 *
 * ── Why this is not one behaviour ─────────────────────────────────────
 * The seam refuses a batch for two structurally different reasons, and
 * the correct response to each is the opposite of the other:
 *
 *   ENTRY-INVALID — a specific entry's bytes will never be acceptable
 *   (malformed, expired, unregistered/inactive domain, duplicate wire or
 *   intent id, unpriceable op). Drop it, retry the rest. Unchanged
 *   behaviour, and it is what this loop has always done.
 *
 *   CAPACITY — every entry is fine; the BLOCK is full. Before the
 *   propose-time check became meter-aware this case could not be seen
 *   here at all: it first appeared at COMMIT, where it is a whole-block
 *   verdict, and the round died with BATCH COMMIT FAILED. Handled as if
 *   it were entry-invalid it would be worse than useless — a perfectly
 *   valid transaction destroyed to make room a shorter batch would have
 *   had anyway. So: propose the prefix that fits and put the tail BACK.
 *
 * ── Truncation happens at PROPOSAL FORMATION ONLY ─────────────────────
 * Truncating inside the ENGINE would be a consensus bug and is
 * deliberately not implemented anywhere: the round's vote binds the batch
 * digest (round_state.tx_hash is the proposal's tx_root, votes carry it
 * as vote_target, and followers compare it), so committing a truncated
 * subset would commit a block that differs from the one voted on. Here,
 * before any digest exists, WHICH entries the leader proposes is already
 * leader discretion — the fee ordering and the staleness drops above are
 * the same discretion. Nothing about the set of blocks a follower or the
 * engine ACCEPTS changes; no wire format, protocol version or schema is
 * touched.
 *
 * ── Determinism ───────────────────────────────────────────────────────
 * Every decision comes from the seam's verdict, which is a function of
 * the entry bytes, their order and committed state. Two honest leaders
 * handed the same popped batch shape it identically. Leaders are not
 * required to agree on batch CONTENT anyway (mempools differ), but they
 * must never disagree about VALIDITY — and this function only ever
 * proposes a prefix the seam has just accepted whole.
 *
 * Termination: every iteration either returns or strictly decreases
 * `valid`, which starts at count <= NODUS_W_MAX_BLOCK_TXS.
 *
 * Non-static so test executables (compiled with NODUS_WITNESS_INTERNAL_API
 * via register_witness_test) can drive the shaping directly, without a
 * live round; the apply_tx_to_state precedent above. Not declared in any
 * public header — the one production caller is immediately below.
 *
 * @return >0 propose batch[0 .. rc-1]; 0 nothing left to propose;
 *         -1 node-local fault (everything requeued — open no round).
 */
int nodus_witness_bft_shape_successor_batch(
        nodus_witness_t *w,
        nodus_witness_mempool_entry_t **batch,
        int count) {
    if (!w || !batch || count <= 0 || count > NODUS_W_MAX_BLOCK_TXS)
        return -1;

    int valid = count;
    while (valid > 0) {
        int bfail = 0;
        nodus_v2_batch_check_result_t res;
        memset(&res, 0, sizeof(res));   /* the callee fills it on entry;
                                         * zeroed first so no compiler and
                                         * no reader has to prove that   */
        int brc = nodus_witness_v2_produce_batch_check_ex(w, batch, valid,
                                                          &bfail, &res);
        if (brc == 0) return valid;              /* proposable as it is   */

        if (brc != -1 || bfail < 0 || bfail >= valid) {
            /* A node-local fault, or an index this node cannot trust.
             * Nothing here is any submitter's fault: requeue it all and
             * open no round. */
            QGP_LOG_ERROR(LOG_TAG, "successor batch check faulted (rc=%d "
                          "kind=%d) — requeueing %d entries, no round",
                          brc, (int)res.kind, valid);
            shape_requeue(w, batch, 0, valid);
            return -1;
        }

        if (res.kind == NODUS_V2_BATCH_FAIL_CAPACITY_UNITS && bfail > 0) {
            /* The block ran out of UNITS at bfail: entries [0, bfail)
             * reserved successfully in this very call, so that prefix is
             * exactly what fits. Propose it and put the tail back — no
             * valid entry is destroyed and no client loses its receipt.
             * The re-check below is guaranteed to pass (a prefix of an
             * accepted reservation sequence, summing to fewer bytes and
             * holding a subset of the identities), and it is run anyway
             * so that what we propose is always something the seam has
             * accepted WHOLE. */
            QGP_LOG_WARN(LOG_TAG, "successor batch over the unit budget at "
                         "%d — truncating to %d, requeueing %d (meter "
                         "status %d)", bfail, bfail, valid - bfail,
                         (int)res.meter_status);
            shape_requeue(w, batch, bfail, valid);
            valid = bfail;
            continue;
        }

        if (res.kind == NODUS_V2_BATCH_FAIL_CAPACITY_BYTES) {
            /* The absolute block-BYTE bound is a whole-batch SUM taken
             * BEFORE any reservation, so the seam reports fail_index 0
             * no matter which envelope crossed the bound
             * (nodus_witness_v2_env.c, step 4b). Reading that 0 as "entry
             * 0 is poison" would destroy an innocent entry — which is why
             * this case cannot share the meter path's truncate-at-index.
             * Shrink from the TAIL instead, one entry per pass, bounded
             * by the batch size (<= NODUS_W_MAX_BLOCK_TXS iterations).
             * At valid == 1 the single entry alone exceeds the bound and
             * can never fit any block, so it is genuinely poison and is
             * dropped rather than requeued forever. */
            if (valid == 1) {
                QGP_LOG_WARN(LOG_TAG, "a single successor entry exceeds the "
                             "block byte bound — dropping it");
                shape_drop(batch, 0, &valid);
            } else {
                QGP_LOG_WARN(LOG_TAG, "successor batch over the block byte "
                             "bound — requeueing the last of %d", valid);
                shape_requeue(w, batch, valid - 1, valid);
                valid--;
            }
            continue;
        }

        if (res.kind == NODUS_V2_BATCH_FAIL_ENTRY_INVALID ||
            res.kind == NODUS_V2_BATCH_FAIL_CAPACITY_UNITS) {
            /* ENTRY_INVALID: today's behaviour, unchanged — the offender
             * is dropped (freed; its submitter re-submits) and the
             * survivors retried.
             *
             * CAPACITY_UNITS at bfail == 0 lands here too, and that is
             * the right disposal: index 0 is judged against the FULL
             * block budget, so an entry that misses there cannot fit an
             * EMPTY block either. Requeueing it would re-poison every
             * future round; dropping lets it self-evict in one. */
            QGP_LOG_WARN(LOG_TAG, "successor batch entry %d rejected by the "
                         "seam (kind=%d seam=%d pf=%d meter=%d) — dropping "
                         "it", bfail, (int)res.kind, (int)res.env_status,
                         (int)res.pf_status, (int)res.meter_status);
            shape_drop(batch, bfail, &valid);
            continue;
        }

        /* NONE with a non-zero return is not reachable from the seam's
         * contract; treat any unexpected classification the conservative
         * way — destroy nothing. */
        QGP_LOG_ERROR(LOG_TAG, "successor batch check returned an "
                      "unexpected classification (%d) — requeueing %d, no "
                      "round", (int)res.kind, valid);
        shape_requeue(w, batch, 0, valid);
        return -1;
    }
    return 0;
}

int nodus_witness_bft_start_round_from_mempool(nodus_witness_t *w) {
    if (!w || w->mempool.count == 0) return -1;

    /* Pop batch from mempool (highest fee first).
     *
     * Hard-Fork v1 / Stage D: the effective batch cap is
     *     min(NODUS_W_MAX_BLOCK_TXS, chain_config.max_txs_per_block)
     * Compile-time NODUS_W_MAX_BLOCK_TXS stays the hard upper bound so
     * the stack-allocated batch[] array remains size-safe; runtime
     * override only tightens. Default when no override exists: the
     * compile-time cap, preserving current semantics. */
    uint64_t current_tip = 0;
    if (w->db) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(w->db,
                "SELECT MAX(block_height) FROM blocks",
                -1, &st, NULL) == SQLITE_OK) {
            if (sqlite3_step(st) == SQLITE_ROW &&
                sqlite3_column_type(st, 0) != SQLITE_NULL) {
                current_tip = (uint64_t)sqlite3_column_int64(st, 0);
            }
            sqlite3_finalize(st);
        }
    }
    /* O15J Block 2 (A2) — ABSTAIN, do not guess.
     *
     * A governance cap this node cannot read is not "no cap". Failing the
     * round here is proportionate and NOT a permanent halt: the caller
     * treats -1 as "no proposal this tick" and the next tick retries, so a
     * transient fault costs one round and a persistent one is handled by
     * view change. Under the same fault finalize_block's INFLATION_START
     * read above would fail too, so this node could not have committed the
     * block it was about to propose anyway.
     *
     * This check sits BEFORE nodus_witness_mempool_pop_batch deliberately:
     * abstaining must not pop and strand queued transactions. */
    uint64_t max_override = 0;
    if (nodus_chain_config_get_u64(w,
                                    DNAC_CFG_MAX_TXS_PER_BLOCK,
                                    current_tip,
                                    (uint64_t)NODUS_W_MAX_BLOCK_TXS,
                                    &max_override) < 0) {
        QGP_LOG_ERROR(LOG_TAG, "start_round: MAX_TXS_PER_BLOCK unreadable at "
                      "tip %llu — abstaining from this round rather than "
                      "proposing under a guessed cap",
                      (unsigned long long)current_tip);
        return -1;
    }
    int effective_max = (max_override < (uint64_t)NODUS_W_MAX_BLOCK_TXS)
                         ? (int)max_override
                         : NODUS_W_MAX_BLOCK_TXS;
    if (effective_max < 1) effective_max = 1;

    nodus_witness_mempool_entry_t *batch[NODUS_W_MAX_BLOCK_TXS];
    int count = nodus_witness_mempool_pop_batch(&w->mempool, batch,
                                                  effective_max);
    if (count <= 0) return -1;

    /* Q7 / CC-GOV-008 — exclusive-block rule for chain_config_tx.
     * If the popped batch contains a DNAC_TX_CHAIN_CONFIG TX mixed with
     * other TX types, strip down to just the chain_config and push the
     * others back into mempool for a future round. This ensures
     * governance events always occupy their own block — unmissable in
     * block explorers, impossible to bury under unrelated spends.
     * Follower-side rejection of violating proposals lives below in
     * the propose handler (layer 2 defense). */
    {
        int cc_idx = -1;
        for (int i = 0; i < count; i++) {
            if (batch[i]->tx_type == NODUS_W_TX_CHAIN_CONFIG) {
                cc_idx = i;
                break;
            }
        }
        if (cc_idx >= 0 && count > 1) {
            /* Push non-cc entries back to mempool (re-sorted by fee),
             * keep only the chain_config entry. */
            nodus_witness_mempool_entry_t *keep = batch[cc_idx];
            for (int i = 0; i < count; i++) {
                if (i != cc_idx) {
                    if (nodus_witness_mempool_add(&w->mempool, batch[i]) != 0) {
                        /* mempool full — free rather than drop on floor */
                        nodus_witness_mempool_entry_free(batch[i]);
                    }
                }
            }
            batch[0] = keep;
            count = 1;
            QGP_LOG_INFO(LOG_TAG,
                "Q7: chain_config_tx batch-isolated (others requeued)");
        }
    }

    /* Re-verify each TX (mempool entries may be stale due to
     * double-spend from a concurrent batch on another view) */
    /* Track all nullifiers seen in this batch to prevent intra-batch double-spend.
     * Max: NODUS_W_MAX_BLOCK_TXS(10) * NODUS_T3_MAX_TX_INPUTS(16) = 160 entries */
    uint8_t seen_nullifiers[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS]
                           [NODUS_T3_NULLIFIER_LEN];
    int seen_count = 0;

    /* Phase 4 / Task 4.1: layer-2 chained UTXO defense.
     *
     * Track the future nullifiers of every output produced by an earlier
     * TX in the batch. When verifying TX[i]'s INPUT nullifiers, reject
     * the entire batch if any input matches an output future-nullifier
     * from TX[j] where j < i — that means TX[i] is trying to spend a
     * UTXO that TX[j] just created, which is forbidden inside a single
     * block (the Phase 6 commit_batch wrapper applies all TXs against
     * the SAME pre-batch UTXO snapshot). */
    uint8_t seen_output_nfs[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS]
                           [NODUS_T3_NULLIFIER_LEN];
    int seen_output_nf_count = 0;

    int valid = 0;
    for (int i = 0; i < count; i++) {
        bool reject = false;

        for (int j = 0; j < batch[i]->nullifier_count; j++) {
            /* Check against DB (already committed) */
            if (nodus_witness_nullifier_exists(w, batch[i]->nullifiers[j])) {
                QGP_LOG_WARN(LOG_TAG, "mempool TX stale (DB double-spend), dropping");
                reject = true;
                break;
            }
            /* Check against other TXs in this batch (intra-batch double-spend) */
            for (int k = 0; k < seen_count; k++) {
                if (memcmp(seen_nullifiers[k], batch[i]->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN) == 0) {
                    QGP_LOG_WARN(LOG_TAG, "intra-batch double-spend detected, "
                                 "dropping TX %d", i);
                    reject = true;
                    break;
                }
            }
            if (reject) break;
            /* Layer 2: chained-UTXO check — input must not match any
             * earlier TX's output future-nullifier. */
            for (int k = 0; k < seen_output_nf_count; k++) {
                if (memcmp(seen_output_nfs[k], batch[i]->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN) == 0) {
                    QGP_LOG_WARN(LOG_TAG,
                        "layer-2: intra-batch chained UTXO detected at TX %d, "
                        "rejecting entire batch", i);
                    reject = true;
                    break;
                }
            }
            if (reject) break;
        }

        if (reject) {
            nodus_witness_mempool_entry_free(batch[i]);
            batch[i] = NULL;
        } else {
            /* Record this TX's nullifiers as seen */
            for (int j = 0; j < batch[i]->nullifier_count; j++) {
                if (seen_count < NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS) {
                    memcpy(seen_nullifiers[seen_count], batch[i]->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN);
                    seen_count++;
                }
            }

            /* Layer 2: append this TX's output future-nullifiers so
             * subsequent batch entries can detect chained-UTXO attempts. */
            uint8_t out_nfs[NODUS_T3_MAX_TX_INPUTS][NODUS_T3_NULLIFIER_LEN];
            int n_out = nodus_extract_output_nullifiers(batch[i]->tx_data,
                                                          batch[i]->tx_len,
                                                          out_nfs,
                                                          NODUS_T3_MAX_TX_INPUTS);
            for (int j = 0; j < n_out; j++) {
                if (seen_output_nf_count <
                    NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS) {
                    memcpy(seen_output_nfs[seen_output_nf_count], out_nfs[j],
                           NODUS_T3_NULLIFIER_LEN);
                    seen_output_nf_count++;
                }
            }

            if (valid != i)
                batch[valid] = batch[i];
            valid++;
        }
    }

    if (valid == 0) {
        QGP_LOG_WARN(LOG_TAG, "all batch TXs stale, skipping");
        w->mempool.last_block_time_ms = nodus_time_now() * 1000ULL;
        return -1;
    }

    /* O15D / capacity season — SUCCESSOR batch hygiene AND capacity fit:
     * run the engine's own pre-commit seam over the candidate batch
     * (decode, committed ruleset context, chain binding, expiry, wire-
     * AND intent-level dedup, block-byte bound, unit reservation), then
     * shape the batch to what the engine will accept. An entry the engine
     * would reject at apply is a WHOLE-BLOCK verdict there, so an invalid
     * offender is dropped HERE and a batch that merely does not FIT is
     * truncated with its tail requeued. See the function above for why
     * those two must not share one disposal. */
    if (w->v2_successor) {
        valid = nodus_witness_bft_shape_successor_batch(w, batch, valid);
        if (valid <= 0) {
            w->mempool.last_block_time_ms = nodus_time_now() * 1000ULL;
            return -1;
        }
    }

    /* Start batch BFT round */
    QGP_BENCH_START(QGP_BENCH_BFT_ROUND);
    int rc = bft_start_round_internal(w, batch, valid);
    QGP_BENCH_END(QGP_BENCH_BFT_ROUND);
    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "batch start_round failed: %d", rc);
        /* Put entries back into mempool or free them */
        for (int i = 0; i < valid; i++) {
            if (batch[i]) {
                int add_rc = nodus_witness_mempool_add(&w->mempool, batch[i]);
                if (add_rc != 0)
                    nodus_witness_mempool_entry_free(batch[i]);
            }
        }
    }

    w->mempool.last_block_time_ms = nodus_time_now() * 1000ULL;
    return rc;
}

/* ════════════════════════════════════════════════════════════════════
 * Handle PROPOSAL (follower receives from leader)
 *
 * F-CONS-06 invariant (mandatory independent state_root recompute):
 *   The wire-format nodus_t3_propose_t does NOT carry a leader-claimed
 *   state_root, and no code path below signs PREVOTE on the basis of
 *   a leader-supplied state_root. Every follower runs
 *   nodus_witness_verify_transaction() on each batch TX and validates
 *   block_hash from the batch's own tx_hashes — no "trust-leader"
 *   fast-path exists.
 *
 *   After COMMIT, each follower calls
 *   nodus_witness_merkle_compute_state_root() against its own DB
 *   (see handle_commit at the bottom of this file) and compares the
 *   result against the leader's COMMIT-message state_root. A
 *   compromised leader therefore cannot force followers to adopt an
 *   invalid post-block state.
 *
 *   DO NOT add a field to nodus_t3_propose_t that carries a leader-
 *   claimed state_root followers sign without local recompute — that
 *   would reintroduce the exact fast-path F-CONS-06 forbids. See
 *   design doc 2026-04-17-witness-stake-delegation-design.md §F-CONS-06
 *   and the regression test tests/test_prevote_state_root_mutation.c
 *   before editing this flow.
 *
 * A2 fix — block_height is leader-claimed but LOCALLY VALIDATABLE:
 *   prop->block_height carries the round's anchor so PREPARED-preimage
 *   signing is consistent across drift. The follower re-checks
 *   prop->block_height == nodus_witness_block_height(w) + 1 before
 *   accepting; mismatch → reject + sync. This does NOT violate
 *   F-CONS-06 because (a) height is a single uint64_t with a trivial
 *   local oracle, not an independent state computation, and (b) the
 *   leader gains no new authority — they could already drive height by
 *   choosing whether to commit the prior block. The field anchors
 *   round identity; it does not substitute for state recompute.
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_handle_propose(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    /* C3 fix: refuse all BFT participation once safety_halt is latched. */
    if (w->safety_halt) {
        fprintf(stderr, "%s: propose rejected — safety halt (h=%llu)\n",
                LOG_TAG, (unsigned long long)w->halt_block_height);
        return -1;
    }

    const nodus_t3_propose_t *prop = &msg->propose;
    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay CHECK — pure, records nothing. The matching nonce_record is
     * below the leader/committee block (O15O Faz 5). */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    /* F17 A2 — transport-layer roster swap (gossip discovery). Consensus
     * authority is NOT tied to this swap anymore; bft_config refreshes
     * from committee below. */
    if (w->pending_roster_ready &&
        w->pending_roster.n_witnesses != w->roster.n_witnesses) {
        memcpy(&w->roster, &w->pending_roster, sizeof(nodus_witness_roster_t));
        w->pending_roster_ready = false;
    }

    /* F17 A2 — recompute BFT config from the chain-derived committee
     * for the block this proposal is for. A3 will additionally gate
     * the leader check against this committee (not w->roster). */
    {
        /* O15O Faz 1 — the quorum this handler will vote under comes from
         * the committee at this height. A fault answering 0 would load
         * the committee (and therefore the quorum) for height 1. Refuse
         * the proposal, exactly as the refresh failure below does. */
        uint64_t tip = 0;
        if (nodus_witness_block_height_checked(w, &tip) != 0) {
            fprintf(stderr, "%s: PROPOSE — chain-height read faulted; "
                    "refusing rather than refreshing the quorum from the "
                    "committee at height 1\n", LOG_TAG);
            return -1;
        }
        uint64_t next_bh = tip + 1;
        if (refresh_bft_config_from_committee(w, next_bh) != 0) {
            fprintf(stderr, "%s: failed to load committee for block %llu\n",
                    LOG_TAG, (unsigned long long)next_bh);
            return -1;
        }
    }

    /* Check for existing round in progress */
    if (w->round_state.phase != NODUS_W_PHASE_IDLE) {
        fprintf(stderr, "%s: proposal rejected — round in progress (phase=%d)\n",
                LOG_TAG, w->round_state.phase);
        return -1;
    }

    /* F17 A3 — verify proposal is from the committee-derived leader for
     * the target block. F17 A5 bootstrap — if committee empty (pre-
     * genesis), fall back to gossip roster. */
    {
        /* O15O Faz 1 — this height selects the committee the proposal's
         * sender is ranked against. A fault answering 0 would rank the
         * sender in the height-1 committee. Refuse; same conclusion and
         * same cost as the committee fault a few lines below. */
        uint64_t tip = 0;
        if (nodus_witness_block_height_checked(w, &tip) != 0) {
            fprintf(stderr, "%s: PROPOSE — chain-height read faulted; "
                    "refusing rather than ranking the sender against the "
                    "committee at height 1\n", LOG_TAG);
            return -1;
        }
        uint64_t next_bh = tip + 1;
        nodus_committee_member_t *committee = NULL;
        int count = 0;
        int sender_idx = -1;

        int gossip_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
        if (gossip_idx < 0) {
            fprintf(stderr, "%s: proposal from unknown sender_id\n", LOG_TAG);
            return -1;
        }

        int lc_rc = load_committee_at_height_alloc(w, next_bh, &committee,
                                                     &count);
        if (lc_rc != 0) {
            /* ── O15L Faz 4 / DG-4 / G4 — fail closed, mirroring the
             * shipped VOTE gate (O15J Block 2A). A node that cannot read
             * its committee must not accept a proposal on the authority
             * of the transport roster's sorted rank.
             *
             * DEFENCE IN DEPTH, not the first line: the bft_config
             * refresh above calls the SAME loader at the SAME height, so
             * on a deterministic fault this handler has already returned
             * -1 there. This branch exists so the site does not read as
             * fail-open to the next person, and it catches any future
             * fault whose window falls between the two calls. */
            free(committee);
            fprintf(stderr,
                    "%s: PROPOSE — CANNOT ESTABLISH THE COMMITTEE at "
                    "height %llu (rc=%d%s); refusing the proposal rather "
                    "than ranking the sender in the transport roster\n",
                    LOG_TAG, (unsigned long long)next_bh, lc_rc,
                    w->db ? "" : ", chain database not open");
            return -1;
        }
        if (count > 0) {
            sender_idx = committee_find_pubkey(committee, count,
                                                 w->roster.witnesses[gossip_idx].pubkey);
            free(committee);
            committee = NULL;
        } else {
            free(committee);
            committee = NULL;
            /* rc == 0 && count == 0 — genuine pre-genesis bootstrap:
             * leader is a gossip-roster slot, by SORTED rank, mirroring
             * nodus_witness_bft_is_leader's fallback exactly; the arrival
             * index (gossip_idx) is node-local and MUST NOT decide
             * leadership (BUGS.md 2026-08-04: node7 saw the honest
             * proposer at arrival index 6, every sorted peer at rank 0). */
            count = (int)w->roster.n_witnesses;
            sender_idx = nodus_witness_roster_sorted_find(
                &w->roster, hdr->sender_id);
        }

        /* C7 fix: block-height epoch — cluster-agreed, no clock-skew fork risk */
    uint64_t epoch = next_bh / (uint64_t)DNAC_EPOCH_LENGTH;
        int leader = nodus_witness_bft_leader_index(epoch, hdr->view, count);
        if (sender_idx < 0 || sender_idx != leader) {
            fprintf(stderr,
                    "%s: proposal from non-leader "
                    "(sender_idx=%d, leader=%d, count=%d)\n",
                    LOG_TAG, sender_idx, leader, count);
            return -1;
        }
    }

    /* O15O Faz 5 — RECORD, now that chain_id and the committee-derived
     * LEADER check have both passed and before any state mutation. A
     * sender that is not the leader for this view consumes none of the
     * cache capacity that protects the ones that are.
     *
     * The refusals BELOW this point (view equality, C5 reproposal, the A2
     * height check) therefore leave the frame recorded and a replay of it
     * refused. The refusals ABOVE leave nothing — which is the intended
     * shape: a transient committee-load failure no longer burns the nonce
     * of the delivery that would have succeeded. */
    nonce_record(hdr->sender_id, hdr->nonce, hdr->timestamp);

    /* ── O15N Faz 2C2 — THE VIEW EQUALITY GATE ────────────────────────
     *
     * WHAT THIS REPLACES. Below, at the round-state initialisation, this
     * handler used to execute `w->current_view = hdr->view;`
     * UNCONDITIONALLY and persist it. A PROPOSE is signed by ONE node —
     * the leader for the view IT names — so that line let any node that
     * is the correct leader for SOME view write this node's view
     * counter, in EITHER direction. Lowering is the worse half and is
     * the defect this season exists to close: the leader for a view we
     * have already left could drag us back to it, and `current_view` is
     * what leader election reads. It also masked the NEW_VIEW replay
     * gap (see the O15M note in handle_newview): a node pushed up by a
     * replayed NEW_VIEW was quietly pulled back down here, so the
     * symptom never surfaced.
     *
     * THE RULE NOW: a proposal is for the view we hold, or it is not for
     * us. Never raise, never lower, WRITE NOTHING.
     *
     * PLACED AFTER the leader/committee block above and BEFORE the C5
     * gate below. What that buys, stated exactly rather than
     * approximately: `current_round`, `round_state` and
     * `awaiting_propose_deadline_ms` are all written at the round-state
     * initialisation further down, so a refusal here leaves every one of
     * them untouched, and the C5 binding below is neither cleared nor
     * enforced by a proposal we are not going to take. It is NOT true
     * that nothing at all has been written by this point — the F17 A2
     * transport-roster swap and refresh_bft_config_from_committee both
     * run above, exactly as they do for every other refusal in this
     * handler. Those are node-local transport/config state, not round or
     * view state.
     *
     * THE ASK IS GATED ON THE SENDER BEING AHEAD, and it sits after the
     * committee/leader checks deliberately (O15N round 1, K-6): asking on
     * every mismatch would let any roster member drive a victim into
     * asking peers for proofs instead of participating. A sender at a
     * LOWER view is the one behind us — it can teach us nothing, and it
     * will ask US when it refuses our traffic.
     *
     * COST WHEN WE ARE THE ONE BEHIND: this node declines the round and
     * waits for the proof that moves it. Its own last_prepared lock
     * still refuses conflicting values while it waits, so declining is
     * a liveness cost only — the same trade every fail-closed gate in
     * this file makes. */
    if (hdr->view != w->current_view) {
        fprintf(stderr,
                "%s: PROPOSE at view %u but we hold view %u — refusing; the "
                "view counter moves only on a verified VIEW_OK proof\n",
                LOG_TAG, hdr->view, w->current_view);
        if (hdr->view > w->current_view)
            bft_viewok_send_request(w, hdr->sender_id);
        return -1;
    }

    /* C5 — reproposal enforcement. If a recent NEW_VIEW bound us to a
     * specific tx_hash at a specific height, the first PROPOSE under
     * this view must match. Otherwise the leader is attempting to
     * ignore the prepared cert the cluster carried through view-change.
     * Cleared on first accepted PROPOSE (including mismatch-rejected —
     * we stay bound until a conforming PROPOSE arrives or a fresh
     * NEW_VIEW resets us). */
    if (w->reproposal_required) {
        /* O15O Faz 1 — the C5 gate compares the leader's proposal against
         * OUR next height. A fault answering 0 makes next_bh 1, which
         * almost never equals reproposal_height, so the gate would reject
         * a CONFORMING proposal and keep the binding armed forever. Fail
         * closed explicitly instead of failing closed by accident, so the
         * operator sees the cause. */
        uint64_t tip = 0;
        if (nodus_witness_block_height_checked(w, &tip) != 0) {
            fprintf(stderr, "%s: C5 PROPOSE — chain-height read faulted; "
                    "cannot evaluate the NEW_VIEW reproposal binding — "
                    "rejecting\n", LOG_TAG);
            return -1;
        }
        uint64_t next_bh = tip + 1;
        if (next_bh != w->reproposal_height ||
            memcmp(prop->tx_root, w->reproposal_tx_hash,
                   NODUS_T3_TX_HASH_LEN) != 0) {
            fprintf(stderr, "%s: C5 PROPOSE does not match NEW_VIEW "
                    "reproposal (expected_h=%llu got_h=%llu) — rejecting\n",
                    LOG_TAG,
                    (unsigned long long)w->reproposal_height,
                    (unsigned long long)next_bh);
            return -1;
        }
        /* Match — gate satisfied for this view. */
        w->reproposal_required = false;
        fprintf(stderr, "%s: C5 PROPOSE matches NEW_VIEW reproposal — "
                "gate cleared\n", LOG_TAG);
    }

    /* A2 fix — locally validate the leader-claimed proposed-block height
     * before any state mutation. Drift between leader and this follower
     * would otherwise produce mismatched PREPARED-preimage signatures
     * (the original "PREVOTE cert_sig verify FAILED" loop). Backward-
     * compat: legacy peers send block_height=0; treat that as "unset"
     * and reject so the follower triggers sync_check on the next epoch
     * tick rather than signing under an unknown anchor. */
    {
        /* O15O Faz 1 — this comparison decides whether the follower signs
         * the round's PREPARED preimage at the leader's height. A fault
         * answering 0 would accept a proposal at height 1 and reject
         * every legitimate one. Refuse before any state mutation. */
        uint64_t tip = 0;
        if (nodus_witness_block_height_checked(w, &tip) != 0) {
            fprintf(stderr,
                    "%s: propose rejected — chain-height read faulted; "
                    "cannot validate the leader-claimed block_height\n",
                    LOG_TAG);
            return -1;
        }
        uint64_t expected_height = tip + 1;
        if (prop->block_height == 0) {
            fprintf(stderr,
                    "%s: propose rejected — missing block_height "
                    "(legacy peer or malformed proposal); sync needed\n",
                    LOG_TAG);
            return -1;
        }
        if (prop->block_height != expected_height) {
            fprintf(stderr,
                    "%s: propose rejected — height mismatch "
                    "(proposal=%llu local_next=%llu); sync needed\n",
                    LOG_TAG,
                    (unsigned long long)prop->block_height,
                    (unsigned long long)expected_height);
            return -1;
        }
        /* O15J Faz 3 — the follower-side terminal refusal is deleted with
         * the activation ceremony; see the leader-side note above. */
    }

    /* ── O15O Faz 6 — THE PREPARED-VALUE LOCK, ENFORCED ───────────────
     *
     * ⚠ DO NOT DELETE THIS AS DEAD CODE. It looks unreachable and is not.
     * nodus_witness_bft_prepared_lock_blocks had ZERO production callers
     * until this call existed (BUGS.md O15N-L3) — the refusal the
     * quorum-intersection safety argument in its own header depends on
     * was compiled, documented, unit-tested, and never consulted by the
     * consensus path it was written for.
     *
     * WHAT IT PROTECTS. PRECOMMIT is sent only on locally observed
     * prevote quorum, and `last_prepared` is captured in that same block
     * (:6600-6628), so PRECOMMITTER ⇒ CARRIER: any committed value has
     * >= 2f+1 carriers, hence >= f+1 honest carriers inside every
     * quorum-sized set. Each of those must REFUSE a conflicting value at
     * that height, or a conflicting value can reach quorum and the chain
     * forks. This call is where that refusal happens.
     *
     * HOW THE STATE ARISES — the reason a reader cannot see this path by
     * inspection, and the reason it was lost. Both batch-abort branches
     * below set `round_state.phase = NODUS_W_PHASE_IDLE` and DELIBERATELY
     * leave `last_prepared` intact (the own-quorum cert-gate failure at
     * :6876-6893 and the commit_batch rollback at :6906-6954; both say in
     * as many words that clearing it is a separate consensus decision).
     * Setting IDLE is also what stops check_timeout from firing a
     * VIEW_CHANGE, so no view change arms `reproposal_required`. The same
     * leader, in the same view, then proposes a DIFFERENT value at the
     * same height: the phase gate passes (we are IDLE), the
     * committee/leader gate passes (same leader, same epoch, same view),
     * the O15N view-equality gate passes, the C5 gate is SKIPPED because
     * `reproposal_required` is false, and the height gate passes. Without
     * this call the node prevotes a value conflicting with the one it
     * prepared, and nothing consults the lock.
     *
     * PLACED AFTER THE A2 HEIGHT BLOCK, BEFORE THE ROUND-STATE INIT, and
     * both halves are load-bearing:
     *   - AFTER A2, because the lock is HEIGHT-GATED — it answers false
     *     unless `last_prepared.height == height`. `last_prepared.height`
     *     is the ROUND ANCHOR (`round_state.block_height`, :6600), which
     *     O15L Faz 3 made the anchor rather than a fresh head read. A2 is
     *     what establishes `prop->block_height == local tip + 1`, putting
     *     both sides in ONE domain. Called before A2, the gate would
     *     compare two different things and silently never fire.
     *   - BEFORE the round-state init, so a refusal writes no round or
     *     view state — `current_round`, `round_state` and
     *     `awaiting_propose_deadline_ms` are all written below. Same
     *     property, and the same reasoning, as the O15N view-equality
     *     gate above.
     *
     * THE VALUE IS `prop->tx_root` and the domains match:
     * `last_prepared.tx_hash` is copied from `w->round_state.tx_hash`
     * (:6606), and on this follower path `round_state.tx_hash` is set
     * from `prop->tx_root` (:5607).
     *
     * COST WHEN IT FIRES: this node declines the round. That is a
     * liveness cost only, and it is the trade every fail-closed gate in
     * this file makes — the lock is height-gated, so a value learned
     * through SYNC leaves no stale refusal behind. */
    if (nodus_witness_bft_prepared_lock_blocks(w, prop->block_height,
                                                prop->tx_root)) {
        fprintf(stderr,
                "%s: PREPARED-VALUE LOCK: refusing a conflicting value at "
                "height %llu — we prepared "
                "%02x%02x%02x%02x%02x%02x%02x%02x…, this proposal carries "
                "%02x%02x%02x%02x%02x%02x%02x%02x… (view=%u). A value we "
                "prepared has our PRECOMMIT behind it; prevoting a "
                "different one at the same height is what a fork is made "
                "of\n",
                LOG_TAG, (unsigned long long)prop->block_height,
                w->last_prepared.tx_hash[0], w->last_prepared.tx_hash[1],
                w->last_prepared.tx_hash[2], w->last_prepared.tx_hash[3],
                w->last_prepared.tx_hash[4], w->last_prepared.tx_hash[5],
                w->last_prepared.tx_hash[6], w->last_prepared.tx_hash[7],
                prop->tx_root[0], prop->tx_root[1], prop->tx_root[2],
                prop->tx_root[3], prop->tx_root[4], prop->tx_root[5],
                prop->tx_root[6], prop->tx_root[7], hdr->view);
        return -1;
    }

    /* Initialize round state from proposal.
     *
     * O15N Faz 2C2 — `w->current_view = hdr->view;` USED TO BE THE NEXT
     * LINE, followed by a save_pbft_state whose only purpose was to
     * persist it. Both are gone: the equality gate above has already
     * established hdr->view == w->current_view, so the assignment could
     * only ever be a no-op or the unproven write this slice removes, and
     * a persist of state nothing changed is work with no reader.
     * `round_state.view` below therefore records the same number it
     * always did. */
    w->current_round = hdr->round;

    round_state_free_batch(&w->round_state);
    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.client_conn = NULL;
    w->round_state.round = hdr->round;
    w->round_state.view = hdr->view;
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    /* O15I P2 — DISARM. The leader produced the PROPOSE the deadman was
     * waiting for; there is nothing left to be dead about. Needs its own
     * line: the deadline lives on the witness, not in round_state, so
     * the memset above does not clear it. Unconditional on purpose —
     * reaching this point means the proposal passed the leader check,
     * the height check and the C5 binding gate, which is the strongest
     * liveness evidence this node can get. */
    w->awaiting_propose_deadline_ms = 0;
    /* A2 fix — anchor height from the proposal (already validated above
     * as == local_next). All cert_sig sign/verify within this round
     * reads from round_state.block_height. */
    w->round_state.block_height = prop->block_height;
    w->round_state.phase_start_time = time_ms();
    O15H_DIAG(w, "round_start_follower", hdr->sender_id,
              w->round_state.block_height, w->current_view,
              w->view_change_target, w->round_state.phase,
              w->round_state.phase_start_time, 0, "PROPOSE", 0,
              0, w->bft_config.quorum, "accepted leader proposal");
    w->round_state.proposal_timestamp = hdr->timestamp;
    memcpy(w->round_state.proposer_id, hdr->sender_id,
           NODUS_T3_WITNESS_ID_LEN);

    bool tx_invalid = false;
    char reject_reason[256] = {0};

    if (prop->batch_count > 0) {
        /* ── Batch mode ──────────────────────────────────────────── */
        memcpy(w->round_state.tx_root, prop->tx_root,
               NODUS_T3_TX_HASH_LEN);
        memcpy(w->round_state.tx_hash, prop->tx_root,
               NODUS_T3_TX_HASH_LEN);

        /* Verify block_hash = SHA3-512(all tx_hashes) */
        uint8_t computed_bh[NODUS_T3_TX_HASH_LEN];
        {
            uint8_t hash_input[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_TX_HASH_LEN];
            size_t total_len = 0;
            for (int i = 0; i < prop->batch_count; i++) {
                memcpy(hash_input + total_len,
                       prop->batch_txs[i].tx_hash, NODUS_T3_TX_HASH_LEN);
                total_len += NODUS_T3_TX_HASH_LEN;
            }
            nodus_key_t bh;
            nodus_hash(hash_input, total_len, &bh);
            memcpy(computed_bh, bh.bytes, NODUS_T3_TX_HASH_LEN);
        }

        if (memcmp(computed_bh, prop->tx_root, NODUS_T3_TX_HASH_LEN) != 0) {
            fprintf(stderr, "%s: batch block_hash mismatch — rejecting\n",
                    LOG_TAG);
            tx_invalid = true;
            snprintf(reject_reason, sizeof(reject_reason),
                     "block_hash mismatch");
        }

        /* Q7 / CC-GOV-008 — exclusive-block rule. A proposal containing
         * a DNAC_TX_CHAIN_CONFIG MUST contain only that TX. Rejects
         * proposers that try to bury governance events among spends. */
        if (!tx_invalid) {
            for (int i = 0; i < prop->batch_count; i++) {
                if (prop->batch_txs[i].tx_type == NODUS_W_TX_CHAIN_CONFIG &&
                    prop->batch_count != 1) {
                    fprintf(stderr,
                        "%s: Q7 exclusive-block violation — "
                        "chain_config_tx in batch of %d\n",
                        LOG_TAG, prop->batch_count);
                    tx_invalid = true;
                    snprintf(reject_reason, sizeof(reject_reason),
                             "chain_config_tx must occupy its own block");
                    break;
                }
            }
        }

        /* Allocate batch entries from proposal data.
         * Track nullifiers across TXs to prevent intra-batch double-spend. */
        uint8_t batch_seen_nuls[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS]
                               [NODUS_T3_NULLIFIER_LEN];
        int batch_seen_count = 0;

        /* Follower path: mirror leader's tx_type propagation so unanimous
         * quorum check at handle_vote() fires for GENESIS entries. */
        w->round_state.tx_type = (prop->batch_count > 0)
            ? prop->batch_txs[0].tx_type
            : NODUS_W_TX_SPEND;
        w->round_state.batch_count = prop->batch_count;
        for (int i = 0; i < prop->batch_count && !tx_invalid; i++) {
            const nodus_t3_batch_tx_t *btx = &prop->batch_txs[i];
            nodus_witness_mempool_entry_t *entry = calloc(1, sizeof(*entry));
            if (!entry) { tx_invalid = true; break; }

            memcpy(entry->tx_hash, btx->tx_hash, NODUS_T3_TX_HASH_LEN);
            entry->nullifier_count = btx->nullifier_count;
            for (int j = 0; j < btx->nullifier_count; j++) {
                if (btx->nullifiers[j])
                    memcpy(entry->nullifiers[j], btx->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN);
            }
            entry->tx_type = btx->tx_type;
            /* O15H D8 — family-aware (nodus_t3_tx_size_limit). This is
             * the follower's copy-in of a proposed batch entry; sizing a
             * V2 envelope against the legacy ceiling here would drop the
             * transaction AFTER the leader had already proposed it. */
            if (btx->tx_data && btx->tx_len > 0 &&
                btx->tx_len <= nodus_t3_tx_size_limit(btx->tx_data,
                                                        btx->tx_len)) {
                entry->tx_data = malloc(btx->tx_len);
                if (!entry->tx_data) {
                    free(entry);
                    tx_invalid = true;
                    break;
                }
                memcpy(entry->tx_data, btx->tx_data, btx->tx_len);
                entry->tx_len = btx->tx_len;
            }
            if (btx->client_pubkey)
                memcpy(entry->client_pubkey, btx->client_pubkey, NODUS_PK_BYTES);
            if (btx->client_sig)
                memcpy(entry->client_sig, btx->client_sig, NODUS_SIG_BYTES);
            entry->fee = btx->fee;
            entry->client_conn = NULL;  /* Follower has no client conn */

            /* Verify this TX independently.
             * VALIDATION mode: this is the follower's verdict on the
             * LEADER's proposal, and a single reject drops the whole
             * batch below. It MUST depend only on the TX bytes and
             * committed DB state — never on this node's mempool depth,
             * which differs from the leader's by arrival timing alone. */
            int vrc = nodus_witness_verify_transaction(w,
                          entry->tx_data, entry->tx_len,
                          entry->tx_hash, entry->tx_type,
                          (const uint8_t *)entry->nullifiers,
                          entry->nullifier_count,
                          entry->client_pubkey, entry->client_sig,
                          entry->fee, NODUS_WITNESS_VERIFY_VALIDATION,
                          reject_reason, sizeof(reject_reason));
            if (vrc != 0) {
                fprintf(stderr, "%s: batch TX %d rejected: %s\n",
                        LOG_TAG, i, reject_reason);
                nodus_witness_mempool_entry_free(entry);
                tx_invalid = true;
                break;
            }

            /* Intra-batch double-spend check: reject if any nullifier
             * was already seen in an earlier TX in this batch */
            for (int j = 0; j < entry->nullifier_count && !tx_invalid; j++) {
                for (int k = 0; k < batch_seen_count; k++) {
                    if (memcmp(batch_seen_nuls[k], entry->nullifiers[j],
                               NODUS_T3_NULLIFIER_LEN) == 0) {
                        fprintf(stderr, "%s: batch TX %d intra-batch "
                                "double-spend — REJECTING batch\n",
                                LOG_TAG, i);
                        snprintf(reject_reason, sizeof(reject_reason),
                                 "intra-batch double-spend");
                        nodus_witness_mempool_entry_free(entry);
                        entry = NULL;
                        tx_invalid = true;
                        break;
                    }
                }
            }
            if (tx_invalid) break;

            /* Record nullifiers as seen */
            for (int j = 0; j < entry->nullifier_count; j++) {
                if (batch_seen_count <
                    NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS) {
                    memcpy(batch_seen_nuls[batch_seen_count],
                           entry->nullifiers[j], NODUS_T3_NULLIFIER_LEN);
                    batch_seen_count++;
                }
            }

            w->round_state.batch_entries[i] = entry;
        }

        /* O15D — SUCCESSOR follower batch check: the same engine seam
         * the leader ran (decode, committed ruleset context, chain,
         * expiry, wire+intent dedup, and — capacity season — the block
         * byte bound plus the unit reservation) — deterministic from
         * bytes + committed state, so every honest follower reaches the
         * same verdict on the same proposal. A leader proposing a
         * duplicate intent, a replayed envelope or a batch the block
         * budget cannot pay for is REJECT-voted here instead of killing
         * the block at commit.
         *
         * The VERDICT SEMANTICS are deliberately unchanged: a follower
         * has no batch to shape, so it does not ask WHY the seam refused.
         * Any refusal is a reject_reason and a REJECT vote — which is the
         * same answer the engine would give the block anyway. It keeps
         * calling the classification-free entry for exactly that reason. */
        if (!tx_invalid && w->v2_successor) {
            int bfail = 0;
            if (nodus_witness_v2_produce_batch_check(
                    w, w->round_state.batch_entries,
                    w->round_state.batch_count, &bfail) != 0) {
                fprintf(stderr, "%s: successor proposal failed the batch "
                        "seam (entry %d) — rejecting\n", LOG_TAG, bfail);
                tx_invalid = true;
                snprintf(reject_reason, sizeof(reject_reason),
                         "successor batch seam rejected entry %d", bfail);
            }
        }

        /* Cleanup on invalid batch.
         *
         * Use round_state_free_batch rather than the hand-rolled loop this
         * replaces: that loop freed and NULLed every entry but left
         * batch_count at the value taken from the proposal (:4119), so the
         * round went on CLAIMING N entries it no longer held. That is not
         * cosmetic — we still broadcast a REJECT prevote and stay in the
         * round, and peers can reach quorum without us, so this node can
         * still walk PREVOTE → PRECOMMIT → COMMIT and enter the
         * `batch_count > 0` commit branch with an array of NULLs. The
         * helper zeroes the count as well, which makes that branch
         * unreachable for a rejected batch. */
        if (tx_invalid) {
            round_state_free_batch(&w->round_state);
        }

        fprintf(stderr, "%s: batch proposal from leader: %d TXs, %s\n",
                LOG_TAG, prop->batch_count,
                tx_invalid ? "REJECTED" : "APPROVED");
    } else {
        /* Phase 9 / Task 9.1 — legacy single-TX propose path DELETED.
         * Phase 7 removed the only sender of legacy single-TX proposals
         * (nodus_witness_bft_start_round); after the chain-wipe deploy,
         * no peer ever sends batch_count == 0. Reject defensively. */
        fprintf(stderr, "%s: legacy single-TX propose rejected — "
                "batch_count == 0 unsupported after Phase 7\n", LOG_TAG);
        tx_invalid = true;
        snprintf(reject_reason, sizeof(reject_reason),
                 "legacy single-TX propose unsupported");
    }

    nodus_witness_vote_t my_vote =
        tx_invalid ? NODUS_W_VOTE_REJECT : NODUS_W_VOTE_APPROVE;

    /* C5 — sign PREPARED preimage when voting APPROVE. Failure here falls
     * back to REJECT (witness cannot vouch for the prepared cert) so we
     * still broadcast a PREVOTE rather than going silent. REJECT voters
     * leave cert_sig=0 and do not contribute to the prepared cert. */
    nodus_sig_t prep_sig;
    bool have_prep_sig = false;
    if (my_vote == NODUS_W_VOTE_APPROVE) {
        uint8_t prep_preimage[NODUS_WITNESS_PREPARED_PREIMAGE_LEN];
        /* A2 fix — height comes from round_state (set in handle_propose
         * after sanity-check against local_next), so this signature
         * matches the leader's PREPARED preimage even when local heights
         * have drifted across the cluster. */
        uint64_t prep_height = w->round_state.block_height;
        if (compute_prepared_preimage(w->current_view, prep_height,
                                        w->round_state.tx_hash,
                                        w->chain_id,
                                        prep_preimage) == 0 &&
            nodus_sign_prepared_vote(&prep_sig, prep_preimage,
                                       sizeof(prep_preimage),
                                       &w->server->identity.sk) == 0) {
            have_prep_sig = true;
        } else {
            fprintf(stderr, "%s: prepared vote sign failed — "
                    "falling back to REJECT\n", LOG_TAG);
            my_vote = NODUS_W_VOTE_REJECT;
            tx_invalid = true;
            snprintf(reject_reason, sizeof(reject_reason),
                     "prepared vote sign failed");
        }
    }

    /* Record our own PREVOTE */
    memcpy(w->round_state.prevotes[0].voter_id, w->my_id,
           NODUS_T3_WITNESS_ID_LEN);
    /* F17 A1 — carry our pubkey alongside for committee authorization. */
    memcpy(w->round_state.prevotes[0].pubkey,
           w->server->identity.pk.bytes, DNAC_PUBKEY_SIZE);
    w->round_state.prevotes[0].vote = my_vote;
    w->round_state.prevote_count = 1;
    w->round_state.prevote_approve_count =
        (my_vote == NODUS_W_VOTE_APPROVE) ? 1 : 0;
    if (have_prep_sig) {
        memcpy(w->round_state.prevotes[0].signature, prep_sig.bytes,
               NODUS_SIG_BYTES);
    }

    /* Build and broadcast our PREVOTE */
    nodus_t3_msg_t vote_msg;
    memset(&vote_msg, 0, sizeof(vote_msg));
    vote_msg.type = NODUS_T3_PREVOTE;
    vote_msg.txn_id = ++w->next_txn_id;
    /* Use round_state.tx_hash — set to block_hash in batch mode */
    memcpy(vote_msg.vote.vote_target, w->round_state.tx_hash, NODUS_T3_TX_HASH_LEN);
    vote_msg.vote.vote = (uint32_t)my_vote;
    if (have_prep_sig) {
        memcpy(vote_msg.vote.cert_sig, prep_sig.bytes, NODUS_SIG_BYTES);
    }
    if (tx_invalid)
        snprintf(vote_msg.vote.reason, sizeof(vote_msg.vote.reason),
                 "%s", reject_reason);

    int sent = nodus_witness_bft_broadcast(w, &vote_msg);

    fprintf(stderr, "%s: PREVOTE %s for round %lu (%d batch txs, sent=%d)\n",
            LOG_TAG,
            my_vote == NODUS_W_VOTE_APPROVE ? "APPROVE" : "REJECT",
            (unsigned long)hdr->round, prop->batch_count, sent);

    /* O15C-C D2 — peers' votes that arrived before this proposal did.
     * This is the exact loss that starved round 20 of the 2026-08-19
     * rehearsal: fast peers' PREVOTEs landed while this node was still
     * settling the previous round and were silently ignored. */
    nodus_witness_bft_drain_vote_buffer(w);

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Handle PREVOTE / PRECOMMIT
 * ════════════════════════════════════════════════════════════════════ */

/* O15C-C D2 — park one near-future vote in the bounded buffer.
 * Dedup key is (sender, type, round, view), keep-first, so a repeated
 * frame can never evict an honest entry. A full buffer drops the new
 * entry with a log line — bounded memory beats completeness here, and
 * the sender's vote still counts on every node that was in phase. */
static void bft_vote_buffer_insert(nodus_witness_t *w, uint8_t msg_type,
                                   uint64_t round, uint32_t view,
                                   const uint8_t *sender_id,
                                   const nodus_t3_vote_t *vote) {
    int free_slot = -1;
    for (int i = 0; i < NODUS_W_VOTE_BUFFER_CAP; i++) {
        nodus_witness_pending_vote_t *e = &w->vote_buffer[i];
        if (!e->used) {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        /* Prune entries for rounds that are already settled. */
        if (e->round <= w->last_committed_round) {
            e->used = false;
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (e->msg_type == msg_type && e->round == round &&
            e->view == view &&
            memcmp(e->sender_id, sender_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return;  /* keep-first */
    }
    if (free_slot < 0) {
        fprintf(stderr, "%s: vote buffer full — dropping early %s for "
                "round %llu\n", LOG_TAG,
                msg_type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
                (unsigned long long)round);
        return;
    }
    nodus_witness_pending_vote_t *e = &w->vote_buffer[free_slot];
    memset(e, 0, sizeof(*e));
    e->used = true;
    e->msg_type = msg_type;
    e->round = round;
    e->view = view;
    memcpy(e->sender_id, sender_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(e->vote_target, vote->vote_target, NODUS_T3_TX_HASH_LEN);
    e->vote = vote->vote;
    memcpy(e->reason, vote->reason, sizeof(e->reason));
    memcpy(e->cert_sig, vote->cert_sig, NODUS_SIG_BYTES);
    fprintf(stderr, "%s: buffered early %s for round %llu "
            "(current round %llu, phase %d)\n", LOG_TAG,
            msg_type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
            (unsigned long long)round,
            (unsigned long long)w->round_state.round,
            (int)w->round_state.phase);
}

/* `live_hdr` is the O15O Faz 5 record token, and it is the ONLY reason
 * this function takes a header at all: the committee gate for a vote
 * lives HERE, not in the public entry point, so the record has to travel
 * down with the frame.
 *
 *   non-NULL — a LIVE frame straight off the wire. Its nonce is recorded
 *              immediately below the committee gate.
 *   NULL     — a vote replayed out of w->vote_buffer by
 *              nodus_witness_bft_drain_vote_buffer, which holds no
 *              header. Nothing is recorded, and nothing needs to be:
 *              bft_vote_buffer_insert dedups on
 *              (sender, msg_type, round, view) keep-first, so a
 *              re-presented buffered vote can neither take a second slot
 *              nor displace an honest one, and the duplicate-by-pubkey
 *              check below refuses a second vote from the same sender in
 *              the same round regardless. */
static int bft_handle_vote_inner(nodus_witness_t *w, uint8_t msg_type,
                                 uint64_t round, uint32_t view,
                                 const uint8_t *sender_id,
                                 const nodus_t3_vote_t *vote,
                                 const nodus_t3_header_t *live_hdr);

void nodus_witness_bft_drain_vote_buffer(nodus_witness_t *w) {
    if (!w) return;
    bool progress = true;
    while (progress) {
        progress = false;
        for (int i = 0; i < NODUS_W_VOTE_BUFFER_CAP; i++) {
            nodus_witness_pending_vote_t *e = &w->vote_buffer[i];
            if (!e->used) continue;
            if (e->round <= w->last_committed_round) {
                e->used = false;
                continue;
            }
            bool eligible =
                e->round == w->round_state.round &&
                e->view == w->round_state.view &&
                ((e->msg_type == NODUS_T3_PREVOTE &&
                  w->round_state.phase == NODUS_W_PHASE_PREVOTE) ||
                 (e->msg_type == NODUS_T3_PRECOMMIT &&
                  w->round_state.phase == NODUS_W_PHASE_PRECOMMIT));
            if (!eligible) continue;
            /* Consume before feeding: whatever the handler decides, the
             * entry had its one chance (mirrors the pre-buffer contract
             * where an in-phase arrival was judged exactly once). */
            nodus_witness_pending_vote_t copy = *e;
            e->used = false;
            nodus_t3_vote_t v;
            memset(&v, 0, sizeof(v));
            memcpy(v.vote_target, copy.vote_target, NODUS_T3_TX_HASH_LEN);
            v.vote = copy.vote;
            memcpy(v.reason, copy.reason, sizeof(v.reason));
            memcpy(v.cert_sig, copy.cert_sig, NODUS_SIG_BYTES);
            (void)bft_handle_vote_inner(w, copy.msg_type, copy.round,
                                        copy.view, copy.sender_id, &v,
                                        /*live_hdr*/ NULL);
            progress = true;
        }
    }
}

int nodus_witness_bft_handle_vote(nodus_witness_t *w,
                                    const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    /* C3 fix: refuse all BFT participation once safety_halt is latched. */
    if (w->safety_halt) return -1;

    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay CHECK — pure, records nothing. The matching nonce_record is
     * inside bft_handle_vote_inner, immediately below the committee gate
     * that lives there (O15O Faz 5). */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    if (msg->type != NODUS_T3_PREVOTE && msg->type != NODUS_T3_PRECOMMIT)
        return -1;

    /* O15C-C D2 — near-future votes are buffered, not dropped. Anchor
     * against the live round when one exists, else the last settled
     * round (round_state is memset to 0 on some resets). */
    {
        uint64_t cur = w->round_state.round;
        uint64_t anchor = cur > w->last_committed_round
                              ? cur : w->last_committed_round;
        bool future_round =
            hdr->round > cur &&
            hdr->round <= anchor + NODUS_W_VOTE_BUFFER_ROUND_AHEAD;
        bool early_precommit =
            hdr->round == cur && hdr->view == w->round_state.view &&
            msg->type == NODUS_T3_PRECOMMIT &&
            w->round_state.phase == NODUS_W_PHASE_PREVOTE;
        if (future_round || early_precommit) {
            /* O15O Faz 5 — NOTHING IS RECORDED ON THIS BRANCH, and it is
             * the one place a frame is admitted without ever meeting a
             * committee gate. bft_vote_buffer_insert is what bounds it:
             * it dedups on (sender, msg_type, round, view) with
             * keep-first, so a re-presented frame takes no second slot
             * and can never evict an honest entry. */
            bft_vote_buffer_insert(w, msg->type, hdr->round, hdr->view,
                                   hdr->sender_id, &msg->vote);
            return 0;
        }
    }

    int rc = bft_handle_vote_inner(w, msg->type, hdr->round, hdr->view,
                                   hdr->sender_id, &msg->vote, hdr);
    /* A live vote can flip the phase (PREVOTE quorum → PRECOMMIT), which
     * can make buffered votes eligible — drain opportunistically. */
    nodus_witness_bft_drain_vote_buffer(w);
    return rc;
}

/* O15H D3+D4 — the post-commit bookkeeping the SUCCESSOR path was
 * missing.
 *
 * `nodus_witness_commit_batch` does two things after a durable commit
 * (:7797, :7819): it clears `last_prepared` and it refreshes
 * `bft_config` from the committee for the NEXT height. Successor rounds
 * do not go through commit_batch — both the own-quorum path and the
 * remote-COMMIT path hand the batch to nodus_witness_v2_produce_commit
 * instead, and that engine knows nothing about BFT config or the
 * prepared slot (grep: zero references in nodus_witness_v2_produce.c).
 * So on a successor chain neither step ever ran. Measured on the
 * 2026-08-25 20-node rehearsal:
 *
 *   D3 — node20 committed height 41 and kept quorum=5, then declared
 *        "view change quorum! new view: 4" on FIVE votes while node1,
 *        which had entered round 17 and therefore refreshed via the
 *        round-start / handle_propose sites, required FOURTEEN. Two
 *        quorums for one chain state is a split, not a slow node.
 *   D4 — all 20 nodes committed height 41 before any view-4 traffic,
 *        yet 14 VIEW_CHANGEs still carried a height=41 prepared cert.
 *        The tick-time guard at nodus_witness.c:1141 releases the
 *        resulting binding, so this self-heals today — but it is a
 *        stale cert circulating through the C5 selection, which is
 *        exactly what C5 exists to make impossible.
 *
 * Refresh failure is latched the same way commit_batch latches it: a
 * witness that cannot know its committee must not keep voting. */
void nodus_witness_bft_after_successor_commit(nodus_witness_t *w) {
    if (!w) return;

    /* D4 — the block is durable; the prepared cert protecting it is
     * redundant. Persist the cleared slot so a restart cannot re-attach
     * it to a future VIEW_CHANGE (H-5 discipline, mirrors :7797-7801). */
    w->last_prepared.present = false;

    /* ── O15O Faz 3 — THE PBFT-STATE SAVE IS LOUD, AND IT IS NOT A HALT ──
     *
     * THE RATIONALE IS WRITTEN ONCE, HERE. The other three
     * nodus_witness_db_save_pbft_state call sites in this file — the C5
     * prepared-certificate capture in bft_handle_vote_inner, the new view
     * in bft_view_move_finish, and the cleared slot after a legacy commit
     * in nodus_witness_commit_batch — carry a one-line back-reference to
     * this block rather than repeating it.
     *
     * WHY THE LOSS IS POSSIBLE AT ALL. The chain connection is opened with
     * `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL`
     * (nodus_witness.c:486-487). Under that pair sqlite does not fsync the
     * WAL on every commit, so a row that returned SQLITE_DONE is durable
     * across a PROCESS crash but NOT across a power loss; and a row whose
     * prepare or step FAILED (nodus_witness_db.c,
     * nodus_witness_db_save_pbft_state — both of its -1 returns) was never
     * written at all. Until this phase all four callers discarded that -1,
     * so either loss was SILENT: the node came back at a lower view than
     * it had reached, or without the prepared certificate it had been
     * protecting a value with, and nothing in the log said so. That
     * silence is the defect — nodus/BUGS.md O15N-L6.
     *
     * WHY A LOG AND NOT A HALT. The owner was asked and decided this
     * explicitly: a transient disk fault must NOT remove a witness from
     * consensus. Latching safety_halt here would turn a recoverable local
     * I/O error into the permanent loss of one vote — and, where the fault
     * is shared rather than local (a full filesystem, a read-only remount
     * after a media error), into the simultaneous loss of a whole
     * committee, which is a halt of the chain rather than of one node.
     *
     * The control flow below is therefore DELIBERATELY UNCHANGED: no
     * halt, no retry loop, no early return, at any of the four sites. The
     * only behaviour this phase adds is that the loss stops being silent
     * and names WHICH of the four facts was lost, because those are four
     * different consequences and an operator has to know which one. */
    if (nodus_witness_db_save_pbft_state(w) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "successor commit: the CLEARED prepared slot was NOT persisted "
            "(stale cert height=%llu view=%u) — this node keeps consensus, "
            "but after a restart that stale prepared certificate may "
            "re-attach to a VIEW_CHANGE",
            (unsigned long long)w->last_prepared.height,
            (unsigned)w->last_prepared.view);
    }

    /* O15I P2 — DISARM the propose-wait deadman: the chain ADVANCED, so
     * whatever we were waiting for either happened or stopped mattering.
     * This helper is the successor lane's single post-commit seam — the
     * own-quorum path (:5504), the remote-COMMIT path (:6056) and the
     * SYNC path (nodus_witness_v2_finalize.c:188) all funnel through it,
     * including the case where the block arrives with NO live local
     * round to reset. That last case is exactly the one the phase→IDLE
     * commit resets cannot see, and exactly the one where a spurious
     * rotation would be worst: a node catching up is not entitled to
     * conclude the leader is dead. */
    w->awaiting_propose_deadline_ms = 0;

    /* D3 — the committee (and therefore the quorum) that governs the
     * NEXT height. At a growth boundary this is the step that moves a
     * node from the pre-growth set to the post-growth one. */
    /* O15O Faz 1 — the height read is latched exactly as the refresh
     * failure below is, and for the identical reason: a witness that
     * cannot know which committee governs its next height must not keep
     * voting. Answering 0 here would refresh the quorum from the height-1
     * committee on a chain that just committed a block. */
    uint64_t tip = 0;
    if (nodus_witness_block_height_checked(w, &tip) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "successor commit: chain-height read faulted — latching "
            "safety_halt rather than refreshing the quorum at height 1");
        w->safety_halt = true;
        return;
    }
    uint64_t next_bh = tip + 1;
    if (refresh_bft_config_from_committee(w, next_bh) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "successor commit: bft_config refresh failed (next_bh=%llu) "
            "— latching safety_halt",
            (unsigned long long)next_bh);
        w->safety_halt = true;
    }
}

static int bft_handle_vote_inner(nodus_witness_t *w, uint8_t msg_type,
                                 uint64_t round, uint32_t view,
                                 const uint8_t *sender_id,
                                 const nodus_t3_vote_t *vote,
                                 const nodus_t3_header_t *live_hdr) {
    /* Verify round and view match */
    if (round != w->round_state.round ||
        view != w->round_state.view)
        return 0;  /* Stale vote, ignore */

    /* Verify tx_hash matches */
    if (memcmp(vote->vote_target, w->round_state.tx_hash,
               NODUS_T3_TX_HASH_LEN) != 0) {
        fprintf(stderr, "%s: vote for different tx_hash\n", LOG_TAG);
        return -1;
    }

    /* Determine vote arrays based on message type */
    nodus_witness_vote_record_t *votes;
    int *vote_count;
    int *approve_count;
    nodus_witness_phase_t expected_phase;
    nodus_witness_phase_t next_phase;

    if (msg_type == NODUS_T3_PREVOTE) {
        votes = w->round_state.prevotes;
        vote_count = &w->round_state.prevote_count;
        approve_count = &w->round_state.prevote_approve_count;
        expected_phase = NODUS_W_PHASE_PREVOTE;
        next_phase = NODUS_W_PHASE_PRECOMMIT;
    } else if (msg_type == NODUS_T3_PRECOMMIT) {
        votes = w->round_state.precommits;
        vote_count = &w->round_state.precommit_count;
        approve_count = &w->round_state.precommit_approve_count;
        expected_phase = NODUS_W_PHASE_PRECOMMIT;
        next_phase = NODUS_W_PHASE_COMMIT;
    } else {
        return -1;
    }

    /* Check phase */
    if (w->round_state.phase != expected_phase) {
        /* O15H diag — THE vote-loss counter the diagnosis needs: how many
         * height-42 votes die because this node has already left the
         * round's phase (typically for VIEW_CHANGE). */
        O15H_DIAG(w, "vote_drop_phase", sender_id,
                  w->round_state.block_height, w->current_view,
                  w->view_change_target, w->round_state.phase,
                  w->round_state.phase_start_time, 0,
                  msg_type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
                  0, 0, w->bft_config.quorum,
                  "wrong phase — vote ignored");
        return 0;  /* Wrong phase, ignore */
    }

    /* F17 A3 — resolve sender's pubkey via gossip roster (witness_id →
     * pubkey mapping, safe by A15 because witness_id = H(pubkey)).
     * Envelope sig already verified against this pubkey at
     * witness.c:657-678 before this handler was invoked. */
    int gossip_idx = nodus_witness_roster_find(&w->roster, sender_id);
    if (gossip_idx < 0) {
        fprintf(stderr, "%s: vote from unknown sender\n", LOG_TAG);
        return -1;
    }
    const uint8_t *sender_pk = w->roster.witnesses[gossip_idx].pubkey;

    /* F17 A17 — duplicate check by pubkey (canonical identity).
     * Historical voter_id-based dedup could in principle be bypassed
     * by a node advertising the same pubkey under two witness_ids
     * in gossip. Pubkey dedup closes that edge. */
    for (int i = 0; i < *vote_count; i++) {
        if (memcmp(votes[i].pubkey, sender_pk, DNAC_PUBKEY_SIZE) == 0)
            return 0;  /* Already received */
    }

    /* F17 A3 — committee membership gate. F17 A5 bootstrap — if
     * committee empty (pre-genesis), gossip_idx >= 0 is already
     * sufficient authorization (gossip peer = legitimate pre-genesis
     * witness). Only active for the genesis round itself. */
    {
        nodus_committee_member_t *committee = NULL;
        int count = 0;
        /* O15H D1 — the authority is the round's BLOCK HEIGHT, not its
         * ROUND NUMBER.
         *
         * load_committee_at_height_alloc takes a block height and
         * resolves it to an epoch (nodus_witness_committee.c:467:
         * e_start = height / DNAC_EPOCH_LENGTH * DNAC_EPOCH_LENGTH).
         * Feeding it `round_state.round` fed it a different scale
         * entirely: on the 2026-08-25 rehearsal (E=6) round 17 carried
         * block height 42, so this gate resolved epoch 12 — the
         * PRE-GROWTH 7-member set — while refresh_bft_config_from_
         * committee had already set quorum=14 from epoch 42's 20-member
         * set. Result: 11 of the 13 freshly-activated joiners' PREVOTEs
         * were rejected here as "non-committee", approve stalled at
         * 4/14, and the boundary round was not slow but STRUCTURALLY
         * uncommittable. Every other committee lookup in this file
         * already passes a height (:4520, :6359, :6436, :6730, :6947);
         * this was the sole site that did not.
         *
         * round_state.block_height is the same source the PREPARED
         * preimage signs below (the A2 fix), and handle_propose has
         * already rejected block_height == 0 and any height that is not
         * the local next height — so verifier and signer cannot drift.
         *
         * Behaviour is byte-identical whenever the committee is static
         * across the two epochs, which is every block the production
         * legacy chain has ever produced; it differs only across a
         * committee CHANGE, which is precisely the case that was
         * broken. */
        int lc_rc = load_committee_at_height_alloc(
                        w, w->round_state.block_height, &committee, &count);
        if (lc_rc == 0 && count > 0) {
            int found = committee_find_pubkey(committee, count, sender_pk);
            free(committee);
            if (found < 0) {
                fprintf(stderr,
                        "%s: vote from non-committee member "
                        "(round=%llu height=%llu committee=%d)\n",
                        LOG_TAG,
                        (unsigned long long)w->round_state.round,
                        (unsigned long long)w->round_state.block_height,
                        count);
                return -1;
            }
        } else if (lc_rc != 0) {
            /* O15J Block 2A — A LOOKUP FAILURE IS NOT PRE-GENESIS.
             *
             * This used to share the branch below: any non-success took
             * the "gossip_idx is sufficient authorization" path, so a
             * node that could not READ its committee accepted votes from
             * anyone on the transport roster. Making the chain-config
             * read fail closed (this season) turned that from a rare
             * accident into a reachable state, so the two cases are now
             * separated at the only place that can tell them apart.
             *
             * `count == 0` with rc 0 is a genuine, committed answer:
             * there is no committee yet, and the gossip check really is
             * the authorization. rc != 0 is NOT an answer — it is the
             * absence of one, and a node that cannot establish who is
             * entitled to vote must not count the vote. */
            free(committee);
            fprintf(stderr,
                    "%s: cannot establish the committee at height %llu "
                    "(rc=%d) — refusing the vote rather than authorising "
                    "it on the transport roster alone\n",
                    LOG_TAG,
                    (unsigned long long)w->round_state.block_height, lc_rc);
            return -1;
        } else {
            /* rc == 0 && count == 0 — genuinely pre-genesis: no committee
             * exists yet, so the gossip_idx check above is the
             * authorization, exactly as before. */
            free(committee);
        }
    }

    /* O15O Faz 5 — RECORD, now that the sender is a committee member (or
     * a roster member pre-genesis) and before the vote is counted. Only a
     * LIVE frame carries a header to record; a drained buffer entry does
     * not, and does not need to (see the live_hdr contract at the forward
     * declaration).
     *
     * A refusal BELOW this line — an invalid C5 cert_sig, a full vote
     * array — leaves the frame recorded. A refusal ABOVE it — wrong
     * round, wrong phase, unknown sender, a committee-load fault — leaves
     * nothing, so the retry that would have been counted is not refused
     * as a duplicate. */
    if (live_hdr)
        nonce_record(live_hdr->sender_id, live_hdr->nonce,
                     live_hdr->timestamp);

    /* C5 — verify PREVOTE cert_sig against PREPARED preimage when the
     * vote is APPROVE. REJECT votes do not contribute to the prepared
     * cert and senders leave cert_sig=0. Invalid sig on APPROVE drops
     * the entire vote (protocol violation). */
    if (msg_type == NODUS_T3_PREVOTE &&
        vote->vote == NODUS_W_VOTE_APPROVE) {
        uint8_t prep_preimage[NODUS_WITNESS_PREPARED_PREIMAGE_LEN];
        /* A2 fix — verifier and sender BOTH read height from
         * round_state (set at round init from leader's proposal),
         * eliminating the drift-induced PREVOTE cert_sig verify FAILED
         * loop. */
        uint64_t prep_height = w->round_state.block_height;
        if (compute_prepared_preimage(w->current_view, prep_height,
                                        w->round_state.tx_hash,
                                        w->chain_id,
                                        prep_preimage) != 0) {
            QGP_LOG_WARN(LOG_TAG, "prepared preimage compute failed");
            return -1;
        }
        nodus_sig_t sig_in;
        memcpy(sig_in.bytes, vote->cert_sig, NODUS_SIG_BYTES);
        nodus_pubkey_t pk_in;
        memcpy(pk_in.bytes, sender_pk, NODUS_PK_BYTES);
        if (nodus_verify_prepared_vote(&sig_in, prep_preimage,
                                         sizeof(prep_preimage),
                                         &pk_in) != 0) {
            fprintf(stderr, "%s: PREVOTE cert_sig verify FAILED "
                    "(sender gossip=%d) — dropping vote\n",
                    LOG_TAG, gossip_idx);
            return -1;
        }
    }

    /* ── O15L Faz 3 (F-13) — the PRECOMMIT half of the same check ──────
     *
     * WHY IT HAS TO BE HERE AND NOT LATER. Until this block, a PRECOMMIT's
     * cert_sig was copied into the vote slot unverified (the memcpy below)
     * while its APPROVE still incremented *approve_count, and that count
     * ALONE drives the phase advance a few lines down (`required =
     * w->bft_config.quorum`, `if (*approve_count < required) return 0`,
     * `phase = next_phase`). So a vote whose certificate is worthless
     * could carry the round into COMMIT.
     *
     * That is a DETERMINISM defect, not merely a missing check. The
     * moment the phase advances, every later PRECOMMIT is dropped by the
     * expected_phase guard at the top of this function ("wrong phase —
     * vote ignored"): there is no "wait for more" state to fall back to.
     * A node could therefore reach approve_count == quorum with FEWER
     * than quorum valid certificates and then refuse to commit its own
     * block — and whether it happened depended on vote ARRIVAL ORDER, not
     * on the block. Two honest nodes, same block, different verdicts.
     * The non-malicious trigger is real: a peer in the O15K zeroed-
     * chain_id state signs its cert over chain_id 0 and fails every
     * healthy peer's reconstruction below.
     *
     * PREVOTE has paid exactly this cost per vote since C5 (the block
     * above); this is symmetry restoration, one Dilithium5 verify per
     * event, not a new mechanism. The lazy-verify objection recorded in
     * test_precommit_cert_verify_lazy.c is about the REMOTE path, where a
     * whole cert set arrives at once — it does not apply per vote.
     *
     * ⚠ THE PREIMAGE IS *NOT* THE PREVOTE ONE. PREVOTE signs the 116-byte
     * PREPARED preimage (compute_prepared_preimage). A PRECOMMIT cert is
     * the 144-byte cert preimage, and the four fields are mirrored from
     * the sign side below (the PREVOTE-quorum arm of this same function):
     *   block_hash -> w->round_state.tx_hash   (signer passes the same
     *                 field; the vote_target equality check at the top of
     *                 this function already proved sender and receiver
     *                 hold the same value, and tx_hash == tx_root)
     *   voter_id   -> sender_id                (signer passes w->my_id,
     *                 which is also what fill_header puts in
     *                 hdr->sender_id, so these are the same 32 bytes)
     *   chain_id   -> w->chain_id              (verifier's own, exactly
     *                 as nodus_witness_verify_certs_snapshot does; the
     *                 handler's verify_chain_id gate has already proved
     *                 the sender advertised this same id)
     *   height     -> w->round_state.block_height
     *
     * The height deserves its own note. The sign side computes
     * `nodus_witness_block_height(w) + 1`, but the ROUND ANCHOR is
     * round_state.block_height and the two are equal on every node that
     * is in this round: the leader sets the anchor to block_height(w)+1
     * at round start, and a follower REJECTS any proposal whose height is
     * not its own local next before adopting it. Using the anchor is what
     * makes this gate agree with the remote-COMMIT gate, which verifies
     * these very certificates at cmt->block_height — i.e. at the leader's
     * round_state.block_height. Verifying here at a freshly-read
     * block_height(w)+1 could accept a cert the remote route rejects,
     * which is precisely the DG-5 promise this season exists to keep.
     * (The A2 comment at round start already declares round_state.
     * block_height normative for "all cert_sig signing/verification
     * within this round"; the sign side is the one that drifted.)
     *
     * Scope mirrors PREVOTE exactly: APPROVE only. A REJECT precommit
     * contributes to no certificate and carries cert_sig = 0 — and no
     * production path emits one at all. An invalid signature drops the
     * ENTIRE vote (protocol violation), so it can never reach
     * *approve_count. */
    if (msg_type == NODUS_T3_PRECOMMIT &&
        vote->vote == NODUS_W_VOTE_APPROVE) {
        uint8_t cert_preimage[NODUS_WITNESS_CERT_PREIMAGE_LEN];
        if (nodus_witness_compute_cert_preimage(w->round_state.tx_hash,
                                                  sender_id,
                                                  w->round_state.block_height,
                                                  w->chain_id,
                                                  cert_preimage) != 0) {
            QGP_LOG_WARN(LOG_TAG, "cert preimage compute failed");
            return -1;
        }
        /* RAW verify, matching the sign side (qgp_dsa87_sign) and both
         * cert verifiers in nodus_witness_cert.c — tagging one side only
         * would break the DNAC client, which verifies these same
         * signatures. */
        if (qgp_dsa87_verify(vote->cert_sig, NODUS_SIG_BYTES,
                              cert_preimage, sizeof(cert_preimage),
                              sender_pk) != 0) {
            fprintf(stderr, "%s: PRECOMMIT cert_sig verify FAILED "
                    "(sender gossip=%d, height=%llu) — dropping vote\n",
                    LOG_TAG, gossip_idx,
                    (unsigned long long)w->round_state.block_height);
            return -1;
        }
    }

    /* Record vote.
     *
     * S3 — this bound is the ARRAY capacity (DNAC_MAX_ACTIVE_VALIDATORS,
     * nodus_witness.h round_state), a memory-safety backstop only. The
     * SEMANTIC bound is still the committee size, and it is enforced
     * strictly earlier in this function, before any slot is written:
     *   - the committee-membership gate above rejects (-1) any sender
     *     whose pubkey is not in load_committee_at_height's result, and
     *   - the pubkey dedup loop above returns 0 for a repeat sender.
     * Together those two make vote_count <= committee_count. Reaching
     * this line with a full array therefore means an invariant broke, so
     * it stays a hard reject rather than a silent drop. */
    if (*vote_count >= DNAC_MAX_ACTIVE_VALIDATORS)
        return -1;

    memcpy(votes[*vote_count].voter_id, sender_id,
           NODUS_T3_WITNESS_ID_LEN);
    memcpy(votes[*vote_count].pubkey, sender_pk, DNAC_PUBKEY_SIZE);
    votes[*vote_count].vote = (nodus_witness_vote_t)vote->vote;
    /* Phase 7.5 stored only PRECOMMIT cert_sig. C5 extends this: PREVOTE
     * APPROVE votes also carry a cert_sig (over PREPARED preimage, just
     * verified above) that the PREVOTE-quorum hook copies into
     * w->last_prepared.sigs. REJECT PREVOTE leaves cert_sig=0. */
    if (msg_type == NODUS_T3_PRECOMMIT ||
        (msg_type == NODUS_T3_PREVOTE &&
         vote->vote == NODUS_W_VOTE_APPROVE)) {
        memcpy(votes[*vote_count].signature, vote->cert_sig,
               NODUS_SIG_BYTES);
    }
    (*vote_count)++;

    if (vote->vote == NODUS_W_VOTE_APPROVE)
        (*approve_count)++;

    fprintf(stderr, "%s: %s from gossip %d: %s (approve=%d/%d, quorum=%u)\n",
            LOG_TAG,
            msg_type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
            gossip_idx,
            vote->vote == NODUS_W_VOTE_APPROVE ? "APPROVE" : "REJECT",
            *approve_count, *vote_count, w->bft_config.quorum);

    /* Check for quorum. All TX types use standard BFT 2f+1, including
     * genesis — unanimity was over-specified and blocked liveness when
     * one witness had message delivery asymmetry. Safety still holds:
     * 2f+1 is sufficient to bind a single value across the cluster, and
     * genesis TX content is validated independently (sig, validators,
     * chain_def). Lagging witnesses catch up via block sync. */
    uint32_t required = w->bft_config.quorum;

    /* ── O15O Faz 2 — A QUORUM OF 0 IS NOT A THRESHOLD, IT IS THE ABSENCE
     * OF ONE.
     *
     * nodus_witness_bft_config_init writes quorum = 0 for any n below
     * NODUS_T3_MIN_WITNESSES and calls that branch "consensus disabled"
     * (this file, the config section). The value is ALSO the sentinel
     * nodus_witness_bft_consensus_active reads, so it must stay 0 — but
     * every `<` against it is then vacuously false, and this comparison
     * is the worst place in the file for that to be true.
     *
     * WHAT IT COSTS HERE. `*approve_count` is at least 1 by the time we
     * reach this line (the APPROVE increment sits directly above), so
     * `1 < 0` is false and the FIRST vote to arrive declares quorum. The
     * phase then advances — and the O15L Faz 3 comment above explains why
     * that is irreversible: every later vote of the same type is dropped
     * by the expected_phase gate, there is no "wait for more" state to
     * return to. A node would carry a round into PRECOMMIT, and from
     * there into COMMIT, having observed ONE approval. That is a safety
     * break on the ordinary block path, not a liveness quirk.
     *
     * The refusal is `return 0` — the SAME exit the insufficient-approve
     * case below takes, and for the same reason: the vote itself was
     * well-formed and is already recorded, so it is not a protocol
     * violation (-1). What we decline is to CONCLUDE anything from it.
     * A node whose quorum is 0 is one that does not participate; leaving
     * the round where it is, is exactly that. */
    if (required == 0) {
        fprintf(stderr, "%s: %s vacuous quorum — refusing to advance the "
                "phase on a quorum of 0 (approve=%d/%d, height=%llu). "
                "Consensus is disabled on this node until bft_config is "
                "refreshed from a committee\n", LOG_TAG,
                msg_type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
                *approve_count, *vote_count,
                (unsigned long long)w->round_state.block_height);
        return 0;
    }

    if ((uint32_t)*approve_count < required)
        return 0;  /* Not yet quorum */

    /* ── Quorum reached ──────────────────────────────────────────── */

    fprintf(stderr, "%s: %s QUORUM! approve=%d >= required=%u\n",
            LOG_TAG,
            msg_type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
            *approve_count, required);

    w->round_state.phase = next_phase;
    w->round_state.phase_start_time = time_ms();
    O15H_DIAG(w, "phase_advance", sender_id, w->round_state.block_height,
              w->current_view, w->view_change_target, w->round_state.phase,
              w->round_state.phase_start_time, 0,
              msg_type == NODUS_T3_PREVOTE ? "PREVOTE" : "PRECOMMIT",
              0, (unsigned)*approve_count, required,
              "vote quorum reached, phase advanced");

    if (next_phase == NODUS_W_PHASE_PRECOMMIT) {
        /* PREVOTE quorum → send PRECOMMIT */

        /* C5 — capture the prepared cert. All APPROVE prevotes we've
         * accumulated (their cert_sigs verified by handle_vote's PREPARED
         * check above) get copied into w->last_prepared. This slot is
         * single-entry (highest prepared, not yet committed) and gets
         * cleared on successful commit_batch; on a later view-change
         * initiated by this witness, the VIEW_CHANGE message carries
         * these sigs so the new leader can pick the re-proposal. */

        /* O15L Faz 3 — THE ROUND ANCHOR, not a fresh head read.
         *
         * This was `nodus_witness_block_height(w) + 1`, which contradicts
         * the invariant the round-start code declares in its own words:
         * "All cert_sig signing/verification within this round reads from
         * round_state.block_height, not from a fresh
         * nodus_witness_block_height(w)+1 lookup, so leader and followers
         * agree on the round's height even when local heights have
         * drifted" (the A2 comment on the leader's round init, mirrored on
         * handle_propose's). This was the one cert site that never got the
         * A2 treatment.
         *
         * The two expressions are EQUAL on every node that is in the
         * round, which is why the drift was invisible: the leader sets the
         * anchor to block_height(w)+1 at round start, and a follower
         * REFUSES any proposal whose height is not its own local next
         * before adopting it. They can differ only if this node's head
         * moves between round start and this line — and that is exactly
         * the case A2 exists for.
         *
         * It became load-bearing with this season's tally-time cert check.
         * Before it, a PRECOMMIT cert was never verified per vote, so a
         * drifted signer's certificate was simply copied into a slot and
         * nobody noticed; now every receiver verifies it against the round
         * anchor, so a node signing over its own shifted head would have
         * its vote DROPPED — a liveness loss introduced by making the
         * check exist. Anchoring both sides removes the possibility
         * instead of papering over it.
         *
         * cert_height has TWO consumers and BOTH want the anchor:
         *   1. the 144-byte cert preimage below, and
         *   2. w->last_prepared.height — which must name the height the
         *      PREPARED signatures collected just below were signed over,
         *      and those are signed over round_state.block_height (round
         *      init on the leader, the PREVOTE verify on a follower). A
         *      VIEW_CHANGE carries this height on the wire, and the
         *      receiver rebuilds the 116-byte PREPARED preimage from it in
         *      nodus_witness_bft_verify_prepared_cert — so under drift the
         *      whole prepared certificate, which is the C5 safety
         *      evidence, would fail verification on every peer. That is
         *      the same defect a second time, and one assignment fixes
         *      both. */
        uint64_t cert_height = w->round_state.block_height;
        memset(&w->last_prepared, 0, sizeof(w->last_prepared));
        w->last_prepared.present = true;
        w->last_prepared.height = cert_height;
        w->last_prepared.view = w->current_view;
        w->last_prepared.round = w->round_state.round;
        memcpy(w->last_prepared.tx_hash, w->round_state.tx_hash,
               NODUS_T3_TX_HASH_LEN);
        /* S3 — the bound is the DESTINATION array's capacity.
         * w->last_prepared.sigs is DNAC_MAX_ACTIVE_VALIDATORS entries; the
         * loop used to stop at NODUS_T3_MAX_WITNESSES (128) against a
         * literal-64 array, an overflow that was unreachable only because
         * prevote_count could not exceed 7. Both are now the same
         * constant, and the source array (prevotes) has the same
         * capacity. */
        uint32_t collected = 0;
        for (int i = 0; i < w->round_state.prevote_count &&
                        collected < DNAC_MAX_ACTIVE_VALIDATORS; i++) {
            if (w->round_state.prevotes[i].vote != NODUS_W_VOTE_APPROVE)
                continue;
            memcpy(w->last_prepared.sigs[collected].voter_id,
                   w->round_state.prevotes[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN);
            memcpy(w->last_prepared.sigs[collected].signature,
                   w->round_state.prevotes[i].signature,
                   NODUS_SIG_BYTES);
            collected++;
        }
        w->last_prepared.n_sigs = collected;
        /* H-5: persist last_prepared so VIEW_CHANGE after a restart
         * carries the highest prepared cert this witness saw.
         *
         * O15O Faz 3 — loud, and never a halt. The WAL /
         * synchronous=NORMAL durability boundary that makes the loss
         * possible, and the owner's decision to log rather than halt, are
         * written out once in nodus_witness_bft_after_successor_commit;
         * this site only names the fact IT loses. */
        if (nodus_witness_db_save_pbft_state(w) != 0) {
            fprintf(stderr,
                "%s: the PREPARED CERTIFICATE was NOT persisted "
                "(height=%llu view=%u n_sigs=%u) — this node keeps "
                "consensus and still holds the cert in memory, but after a "
                "restart it cannot prove the value it prepared here\n",
                LOG_TAG, (unsigned long long)cert_height,
                w->current_view, (unsigned)collected);
        }
        fprintf(stderr, "%s: C5 prepared cert captured (height=%llu, "
                "view=%u, n_sigs=%u)\n", LOG_TAG,
                (unsigned long long)cert_height, w->current_view,
                (unsigned)collected);

        /* Phase 7.5 / Task 7.5.2 — sign the cert preimage with our own
         * Dilithium5 SK before recording or broadcasting the precommit.
         * If signing fails (entropy / OOM / Dilithium internal), abort
         * the precommit and let the round time out via view change. */
        uint8_t cert_preimage[NODUS_WITNESS_CERT_PREIMAGE_LEN];
        if (nodus_witness_compute_cert_preimage(w->round_state.tx_hash,
                                                  w->my_id, cert_height,
                                                  w->chain_id,
                                                  cert_preimage) != 0) {
            fprintf(stderr, "%s: cert preimage compute failed — "
                    "aborting precommit\n", LOG_TAG);
            return -1;
        }

        uint8_t cert_sig[NODUS_SIG_BYTES];
        size_t cert_sig_len = 0;
        if (qgp_dsa87_sign(cert_sig, &cert_sig_len, cert_preimage,
                            sizeof(cert_preimage),
                            w->server->identity.sk.bytes) != 0 ||
            cert_sig_len > NODUS_SIG_BYTES) {
            fprintf(stderr, "%s: cert dilithium sign failed — "
                    "aborting precommit\n", LOG_TAG);
            return -1;
        }
        /* Pad sig out to the fixed wire size if the detached
         * signature came back shorter than NODUS_SIG_BYTES. */
        if (cert_sig_len < NODUS_SIG_BYTES)
            memset(cert_sig + cert_sig_len, 0,
                   NODUS_SIG_BYTES - cert_sig_len);

        /* Record our own precommit first */
        memcpy(w->round_state.precommits[0].voter_id, w->my_id,
               NODUS_T3_WITNESS_ID_LEN);
        /* F17 A1 — carry our pubkey alongside for committee authorization. */
        memcpy(w->round_state.precommits[0].pubkey,
               w->server->identity.pk.bytes, DNAC_PUBKEY_SIZE);
        w->round_state.precommits[0].vote = NODUS_W_VOTE_APPROVE;
        memcpy(w->round_state.precommits[0].signature, cert_sig,
               NODUS_SIG_BYTES);
        w->round_state.precommit_count = 1;
        w->round_state.precommit_approve_count = 1;

        /* Broadcast PRECOMMIT (cert_sig embedded in vote payload) */
        nodus_t3_msg_t pc;
        memset(&pc, 0, sizeof(pc));
        pc.type = NODUS_T3_PRECOMMIT;
        pc.txn_id = ++w->next_txn_id;
        memcpy(pc.vote.vote_target, w->round_state.tx_hash,
               NODUS_T3_TX_HASH_LEN);
        pc.vote.vote = NODUS_W_VOTE_APPROVE;
        memcpy(pc.vote.cert_sig, cert_sig, NODUS_SIG_BYTES);

        nodus_witness_bft_broadcast(w, &pc);
        return 0;
    }

    /* next_phase == NODUS_W_PHASE_COMMIT: PRECOMMIT quorum → COMMIT */

    /* O15D — successor-round commit outputs (BlockID, V2 global root,
     * our QC certificate) — filled by the produce seam and consumed by
     * the COMMIT broadcast below. Inert on legacy rounds. */
    nodus_v2_produce_out_t v2out;
    memset(&v2out, 0, sizeof(v2out));
    int v2_prc = 1;                    /* 1 = not a successor round */

    if (w->round_state.batch_count > 0) {
        /* ── Phase 7 / Task 7.6 — multi-tx block via Phase 6 wrappers ──
         *
         * Local-leader commit path. The Phase 6 commit_batch wrapper
         * applies all N TXs against the SAME pre-batch state at one
         * shared block height, then runs a single finalize_block — so a
         * batch of N TXs becomes ONE multi-tx block, not N single-TX
         * blocks. Genesis (always batch_count == 1 under this path)
         * routes through commit_genesis which bootstraps the chain DB. */
        bool batch_failed;
        if (w->v2_successor) {
            /* ── O15D: THE successor handoff — the agreed batch goes
             * through the ONE V2 engine (execute + roots + header +
             * BlockID + atomic persist, all engine-owned). Own-quorum
             * path: this node derived everything itself, so there is
             * nothing to assert against (the legacy NULL-
             * expected_state_root discipline, :5275-5285). */
            v2_prc = nodus_witness_v2_produce_commit(w,
                         w->round_state.batch_entries,
                         w->round_state.batch_count,
                         w->round_state.block_height,
                         w->round_state.proposal_timestamp,
                         w->round_state.proposer_id,
                         NULL, &v2out);
            batch_failed = (v2_prc != 0);
            /* O15H D3+D4 — commit_batch's post-commit steps, which this
             * branch bypasses. Only on success: a failed produce rolled
             * the block back, so the prepared cert still protects a
             * height that has not landed. */
            if (!batch_failed)
                nodus_witness_bft_after_successor_commit(w);
        } else if (w->round_state.batch_count == 1 &&
            w->round_state.batch_entries[0] &&
            w->round_state.batch_entries[0]->tx_type == NODUS_W_TX_GENESIS) {
            nodus_witness_mempool_entry_t *ge =
                w->round_state.batch_entries[0];
            batch_failed = (nodus_witness_commit_genesis(w, ge->tx_hash,
                                ge->tx_data, ge->tx_len,
                                w->round_state.proposal_timestamp,
                                w->round_state.proposer_id) != 0);
        } else {
            /* Own-quorum commit path — NOT leader-only. Any witness that
             * accumulates a precommit quorum locally arrives here;
             * handle_vote gates on phase alone (:4368), never on
             * is_leader. (The old "Leader path" label was misleading, and
             * it is exactly this property that lets the cluster make
             * progress when one node suppresses its COMMIT frame below.)
             *
             * expected_state_root is NULL: this node computed the root
             * itself, so there is nothing to compare against — which also
             * means finalize_block's C3 divergence check is SKIPPED here
             * (it is gated on expected_state_root != NULL, :3280). Only
             * the handle_commit path supplies one (:5071).
             *
             * Pass round_state.block_height (set at handle_propose's A2
             * fix or local round-init) as expected_height. */

            /* ── O15L Faz 3 (DG-5, DG-6 · G5) — the own-quorum route's
             * certificate gate. ────────────────────────────────────────
             *
             * Three routes reach commit_batch and only two of them used to
             * check that the block carries a quorum of valid witness
             * certificates: the remote COMMIT handler and the sync replay
             * path. THIS one — reached by ANY witness that accumulates a
             * local precommit quorum, not just the leader — checked
             * nothing. A node would therefore persist, and then broadcast,
             * a block on the strength of a vote COUNT alone.
             *
             * The gate is the mirror of the remote handler's: the same
             * nodus_witness_verify_certs_snapshot, over the committed
             * committee snapshot for this block's height, with the same
             * chain_id, and the quorum taken from that snapshot
             * (rv_quorum) rather than w->bft_config.quorum. Same inputs,
             * same verdict — so a block this node commits is a block the
             * remote route would accept.
             *
             * The inputs are the same values the COMMIT frame built below
             * puts on the wire, which is what makes "same inputs" true:
             * tx_root is c_msg.commit.tx_root, block_height is
             * c_msg.commit.block_height, and the certificate array is
             * c_msg.commit.certs / n_precommits — all precommits in slot
             * order, capped identically at NODUS_T3_MAX_WITNESSES. The
             * verifier drops a non-member, a duplicate signer or a bad
             * signature individually and never rejects the whole batch, so
             * the cap and the order cannot change the verdict.
             *
             * It goes HERE rather than inside commit_batch (DG-6): that
             * function takes no certificate parameter, and moving the gate
             * in would double-verify the two routes that already passed.
             *
             * The genesis and successor arms above are deliberately not
             * gated. Genesis (height 1) has no committed committee to be
             * the authority yet — the remote handler skips it for the same
             * reason — and a successor round's finalization artifact is
             * the QC V2, not the legacy cert table.
             *
             * ⚠ AFTER the tally-time cert verify added earlier in this
             * function, a HEALTHY node can no longer fail this gate: every
             * cert in round_state.precommits has already been verified
             * once, our own included (it is signed for real before being
             * recorded in slot 0). So a failure here is not a routine
             * outcome to be logged and shrugged at — it means the local
             * committee authority is unreadable or disagrees with the one
             * the signers used. Treat it as the bug signal it is. */
            {
                /* Same stack array as the remote handler builds, and
                 * deliberately not the heap form the S3 note above
                 * prescribes for DNAC_MAX_ACTIVE_VALIDATORS committee
                 * arrays: this does not raise the process's peak stack.
                 * The remote-COMMIT path already carries an identical
                 * NODUS_T3_MAX_WITNESSES cert array into commit_batch
                 * from the same dispatch depth on the same epoll thread,
                 * so the two commit routes now cost the same frame
                 * rather than one costing more than the other. */
                nodus_t3_sync_cert_t own_certs[NODUS_T3_MAX_WITNESSES];
                uint32_t oc = w->round_state.precommit_count > 0
                            ? (uint32_t)w->round_state.precommit_count : 0u;
                if (oc > (uint32_t)NODUS_T3_MAX_WITNESSES)
                    oc = (uint32_t)NODUS_T3_MAX_WITNESSES;
                for (uint32_t ci = 0; ci < oc; ci++) {
                    memcpy(own_certs[ci].voter_id,
                           w->round_state.precommits[ci].voter_id,
                           NODUS_T3_WITNESS_ID_LEN);
                    memcpy(own_certs[ci].signature,
                           w->round_state.precommits[ci].signature,
                           NODUS_SIG_BYTES);
                }

                uint32_t rv_quorum = 0;
                int cv = nodus_witness_verify_certs_snapshot(w,
                             w->round_state.tx_root,
                             w->round_state.block_height,
                             w->chain_id, own_certs, oc, &rv_quorum);
                if (cv < 0) {
                    /* One message per class. The CONTROL FLOW is identical
                     * for all of them — a node that cannot prove the block
                     * carries a valid quorum does not commit it, whatever
                     * the reason — but the operator needs to be able to
                     * tell a local authority fault from a genuine
                     * shortfall. NODUS_V2_NOT_YET_LINKABLE is deliberately
                     * NOT special-cased: it is dead at this site (this arm
                     * is legacy-only; successors commit through
                     * nodus_witness_v2_produce_commit above, and the legacy
                     * resolver never returns it), so a branch for it would
                     * be untestable code pretending to be a policy. */
                    if (cv == NODUS_V2_INTERNAL_FAULT)
                        QGP_LOG_ERROR(LOG_TAG,
                            "OWN-QUORUM CERT GATE: cannot establish the "
                            "committing committee at height %llu — refusing "
                            "to commit our own block (fail-closed)",
                            (unsigned long long)w->round_state.block_height);
                    else
                        QGP_LOG_ERROR(LOG_TAG,
                            "OWN-QUORUM CERT GATE FAILED at height %llu "
                            "(certs=%u, quorum=%u) — this is a BUG signal: "
                            "every one of these certificates was verified "
                            "when its vote was tallied",
                            (unsigned long long)w->round_state.block_height,
                            oc, rv_quorum);

                    /* F-12 — the round MUST be reset, not merely abandoned.
                     * Returning from here with phase still at COMMIT is a
                     * known regression, documented on the sibling
                     * batch_failed path below: check_timeout would then
                     * necessarily fire a VIEW_CHANGE carrying a
                     * w->last_prepared for a height that never landed,
                     * which a later genuine timeout could bind and
                     * re-propose, dying on tx_invalid and burning another
                     * view. With phase == IDLE check_timeout returns at its
                     * first branch. Same three steps as that path, in the
                     * same order, and last_prepared is likewise left alone
                     * — clearing it is a separate consensus decision. */
                    /* ASCII only: this string goes out on the wire. */
                    bft_emit_batch_replies(w, DNAC_STATUS_ERROR,
                        "certificate quorum not established - not committed");
                    w->round_state.phase = NODUS_W_PHASE_IDLE;
                    w->round_state.client_conn = NULL;
                    return -1;
                }
            }

            batch_failed = (nodus_witness_commit_batch(w,
                                w->round_state.batch_entries,
                                w->round_state.batch_count,
                                w->round_state.block_height,
                                w->round_state.proposal_timestamp,
                                w->round_state.proposer_id,
                                NULL) != 0);
        }

        if (batch_failed) {
            /* The block did NOT persist — commit_batch / commit_genesis
             * rolled the whole batch back. Everything below this point
             * (state_root recompute, COMMIT build, broadcast, cert store,
             * client replies) describes a block that does not exist:
             *
             *   - the COMMIT would carry either the PRE-block state_root
             *     or, when the recompute itself fails, the 64 zero bytes
             *     left by the memset of c_msg. Followers compare that
             *     field literally (finalize_block's C3 check) and latch
             *     w->safety_halt, and halt_auto_recover is off by default
             *     (nodus_witness_sync.c) — so one node's LOCAL failure
             *     would permanently halt the honest majority.
             *   - the client replies would be signed APPROVED receipts
             *     for a rolled-back block.
             *
             * So: no COMMIT broadcast, no cert store, no APPROVED
             * receipt. The clients are told ERROR (they re-submit; a
             * re-proposal of the same entries would need a replay/dedup
             * design that does not exist yet) and the entries are freed
             * by bft_emit_batch_replies.
             *
             * Everything else is BASELINE behaviour, and deliberately so.
             * The round is reset exactly the way the fall-through at the
             * end of this function does it (phase → IDLE, client_conn →
             * NULL), because an earlier revision of this guard returned
             * with phase still at COMMIT and that was a real regression:
             * nodus_witness_bft_check_timeout would then necessarily fire
             * a VIEW_CHANGE on this node, carrying a w->last_prepared for
             * the height we just rolled back while every peer that
             * committed it had cleared theirs — a stale cert that a later
             * genuine timeout could bind and re-propose, dying on
             * tx_invalid and burning another view. With phase == IDLE,
             * check_timeout returns at its first branch (:5752) and no
             * view change happens here at all.
             *
             * w->last_prepared is deliberately NOT cleared: baseline also
             * kept it across a rolled-back commit, so leaving it is not a
             * regression, and clearing it is a separate consensus
             * decision that belongs to its own change. */
            QGP_LOG_ERROR(LOG_TAG, "BATCH COMMIT FAILED round %lu — no COMMIT "
                          "broadcast, clients notified, round reset to IDLE",
                          (unsigned long)w->round_state.round);
            /* ASCII only: this string goes out on the wire to clients. */
            bft_emit_batch_replies(w, DNAC_STATUS_ERROR,
                                   "batch commit failed - block rolled back");

            /* Reset round — mirrors the fall-through path below. */
            w->round_state.phase = NODUS_W_PHASE_IDLE;
            w->round_state.client_conn = NULL;

            /* Returns -1 where the fall-through returns 0. That is a
             * diagnostic distinction only: the single caller discards
             * this value (nodus_witness.c:937), so it is not a
             * behavioural difference from baseline. */
            return -1;
        } else {
            /* Store one commit certificate for the new block. With true
             * multi-tx blocks, batch_count TXs share a single height.
             * O15D: successor rounds skip the LEGACY cert table — their
             * finalization artifact is the QC V2 assembled from the
             * DNA.CERT.v2 exchange (v2_blocks.qc), and writing legacy
             * cert rows into a successor database would be exactly the
             * legacy-lane write the successor role forbids. */
            uint64_t bh = nodus_witness_block_height(w);
            if (!w->v2_successor)
                nodus_witness_cert_store(w, bh, w->round_state.precommits,
                                          w->round_state.precommit_count);

            /* Phase 9 / Task 48 — liveness attendance.
             * C4 fix: attendance is now credited inside commit_batch
             * before finalize_block, atomic with the block persist. The
             * former out-of-txn call here is removed. */

            fprintf(stderr, "%s: BATCH COMMITTED round %lu (%d TXs, height %llu)\n",
                    LOG_TAG, (unsigned long)w->round_state.round,
                    w->round_state.batch_count,
                    (unsigned long long)bh);
            O15H_DIAG(w, "commit", w->my_id, bh, w->current_view,
                      w->view_change_target, w->round_state.phase,
                      w->round_state.phase_start_time,
                      time_ms() - w->round_state.phase_start_time, "-", 0,
                      (unsigned)w->round_state.precommit_approve_count,
                      w->bft_config.quorum, "block committed");
        }
    }
    /* Phase 9 cleanup — legacy single-TX commit branch deleted; every
     * round goes through the batch path above since Phase 7. */

    /* Compute chain state_root (Phase 3 / Task 10: 4-subtree composite).
     * The cached_state_root + COMMIT message field must match what
     * finalize_block wrote into the block row, so we use the same
     * compute_state_root path here.
     * O15D: on a successor round the root the COMMIT frame must carry is
     * the ENGINE-derived V2 global state root — the legacy 4-subtree
     * recompute reads legacy tables a successor never populates, and the
     * engine already returned the committed value; recomputing anything
     * else here would be a second engine. */
    uint8_t utxo_cksum[NODUS_KEY_BYTES];
    bool have_cksum;
    if (w->v2_successor) {
        memcpy(utxo_cksum, v2out.global_root, NODUS_KEY_BYTES);
        have_cksum = true;
    } else {
        have_cksum =
            (nodus_witness_merkle_compute_state_root(w, utxo_cksum) == 0);
    }
    if (have_cksum) {
        char hex[17];
        for (int i = 0; i < 8; i++)
            snprintf(hex + i * 2, 3, "%02x", utxo_cksum[i]);
        fprintf(stderr, "%s: state_root after round %llu: %s\n",
                LOG_TAG, (unsigned long long)w->round_state.round, hex);
        memcpy(w->cached_state_root, utxo_cksum, NODUS_KEY_BYTES);
        w->cached_state_root_valid = true;
    }

    w->last_committed_round = w->round_state.round;

    /* Build and broadcast COMMIT */
    nodus_t3_msg_t c_msg;
    memset(&c_msg, 0, sizeof(c_msg));
    c_msg.type = NODUS_T3_COMMIT;
    c_msg.txn_id = ++w->next_txn_id;

    if (w->round_state.batch_count > 0) {
        /* Batch commit message */
        c_msg.commit.batch_count = w->round_state.batch_count;
        memcpy(c_msg.commit.tx_root, w->round_state.tx_root,
               NODUS_T3_TX_HASH_LEN);
        for (int i = 0; i < w->round_state.batch_count; i++) {
            nodus_witness_mempool_entry_t *e = w->round_state.batch_entries[i];
            if (!e) continue;
            nodus_t3_batch_tx_t *btx = &c_msg.commit.batch_txs[i];
            memcpy(btx->tx_hash, e->tx_hash, NODUS_T3_TX_HASH_LEN);
            btx->nullifier_count = e->nullifier_count;
            for (int j = 0; j < e->nullifier_count; j++)
                btx->nullifiers[j] = e->nullifiers[j];
            btx->tx_type = e->tx_type;
            btx->tx_data = e->tx_data;
            btx->tx_len = e->tx_len;
            btx->client_pubkey = e->client_pubkey;
            btx->client_sig = e->client_sig;
            btx->fee = e->fee;
        }
    }
    /* Phase 9 / Task 9.1 — legacy single-TX commit message build deleted. */

    c_msg.commit.proposal_timestamp = w->round_state.proposal_timestamp;
    memcpy(c_msg.commit.proposer_id, w->round_state.proposer_id,
           NODUS_T3_WITNESS_ID_LEN);
    /* 2026-05-02 Faz 3A bugfix: populate block_height (A2 simetri).
     * Without this, every receiver rejects the COMMIT with "missing
     * block_height (legacy peer or malformed)" — exactly the
     * regression caught by stagef test_view_change_fork. The leader
     * has already proven height authority via handle_propose's A2
     * check; reuse round_state.block_height which finalize_block also
     * used. */
    c_msg.commit.block_height = w->round_state.block_height;
    /* O15D — successor rounds carry our DNA.CERT.v2 certificate over the
     * engine-derived BlockID on the SAME broadcast every node already
     * makes; peers collect+verify it toward the QC. Legacy rounds leave
     * has_v2_cert 0 and the wire unchanged. */
    if (w->v2_successor && v2out.have_cert) {
        c_msg.commit.has_v2_cert = 1;
        memcpy(c_msg.commit.v2_block_id, v2out.block_id,
               NODUS_T3_TX_HASH_LEN);
        memcpy(c_msg.commit.v2_cert_sig, v2out.cert_sig, NODUS_SIG_BYTES);
    }
    c_msg.commit.n_precommits = w->round_state.precommit_count;
    for (int i = 0; i < w->round_state.precommit_count &&
                    i < NODUS_T3_MAX_WITNESSES; i++) {
        memcpy(c_msg.commit.certs[i].voter_id,
               w->round_state.precommits[i].voter_id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(c_msg.commit.certs[i].signature,
               w->round_state.precommits[i].signature,
               NODUS_SIG_BYTES);
    }
    /* The SECOND entrance to the follower halt (2026-07-31, review round 3).
     *
     * The batch_failed guard above covers "the block never persisted". This
     * covers the other half: the block DID persist, and then the post-commit
     * recompute at the top of this section failed. `c_msg` was memset to 0,
     * so broadcasting now would put 64 ZERO bytes in commit.state_root;
     * every follower compares that field literally in finalize_block's C3
     * check and latches w->safety_halt, which halt_auto_recover leaves
     * latched by default. One node's local read fault would stop the honest
     * majority.
     *
     * Both merged hardening rounds widened the fault set that lands here:
     * K3's step-error checks and D2's four fail-close subtree legs are all
     * new ways for compute_state_root to return -1.
     *
     * Producer-side only: we suppress OUR broadcast. The receiver's literal
     * comparison stays exactly as it is — teaching it to skip an all-zero
     * expected_state_root would hand a Byzantine leader a switch to disable
     * fork detection with a field it fully controls.
     *
     * Suppressing does not stall the cluster: this COMMIT branch is not
     * leader-gated (handle_vote checks phase only, :4368), so every other
     * witness reaches it on its own precommit quorum, commits locally and
     * broadcasts its own COMMIT. Our block is already persisted and correct
     * — only our ability to PROVE it to peers is missing, so everything
     * else on this path continues: the cert was stored above,
     * last_committed_round is already advanced, the clients whose TXs did
     * commit still get their APPROVED receipts below, and the round resets
     * to IDLE.
     *
     * HONEST COST of this choice, stated where it is paid: a peer that
     * commits through its OWN handle_vote quorum passes NULL as
     * expected_state_root (:4636), and finalize_block's C3 divergence
     * check is gated on that argument being non-NULL (:3280) — so it
     * never runs on that path. The check only runs for a peer that
     * processes a COMMIT frame via handle_commit, which supplies
     * cmt->state_root (:5071). Suppressing our frame therefore also
     * removes the cross-check opportunity for any peer that would have
     * raced to handle_commit on it. We trade a detection opportunity for
     * the certainty of not halting the majority with an all-zero root;
     * the trade is deliberate, not an oversight. */
    if (have_cksum) {
        memcpy(c_msg.commit.state_root, utxo_cksum, NODUS_KEY_BYTES);
        nodus_witness_bft_broadcast(w, &c_msg);
    } else {
        QGP_LOG_ERROR(LOG_TAG,
            "state_root recompute FAILED after commit (round %lu, height "
            "%llu) — suppressing COMMIT broadcast rather than sending an "
            "all-zero state_root that would halt every follower. Block is "
            "persisted locally; peers commit via their own precommit quorum.",
            (unsigned long)w->round_state.round,
            (unsigned long long)w->round_state.block_height);
    }

    /* Send client responses. Helper is idempotent — noop if already emitted
     * (e.g. via handle_commit remote-COMMIT race path). Reached only when
     * the batch committed: the failure branch above returned. */
    bft_emit_batch_replies(w, DNAC_STATUS_APPROVED, NULL);
    /* Legacy single-TX client response branch deleted in Phase 12 — every
     * round is now batch_count > 0 since Phase 7 removed the single-TX
     * BFT entrypoint. */

    /* Reset round */
    w->round_state.phase = NODUS_W_PHASE_IDLE;
    w->round_state.client_conn = NULL;

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Handle COMMIT (from remote leader / reaching quorum elsewhere)
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_handle_commit(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    /* C3 fix: refuse all BFT participation once safety_halt is latched. */
    if (w->safety_halt) {
        fprintf(stderr, "%s: commit rejected — safety halt (h=%llu)\n",
                LOG_TAG, (unsigned long long)w->halt_block_height);
        return -1;
    }

    const nodus_t3_commit_t *cmt = &msg->commit;
    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay CHECK — pure, records nothing. The matching nonce_record is
     * below the Faz 4 committee gate (O15O Faz 5). */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    /* ── O15O Faz 4 — THE COMMIT SENDER MUST BE A COMMITTEE MEMBER ────
     *
     * WHAT WAS MISSING. Five of the six T3 consumers in this file already
     * resolve the chain-derived committee and check the sender against it
     * (handle_propose:5296, bft_handle_vote_inner:6193, handle_viewchg:8112,
     * handle_viewok:9389, handle_viewok_req:9490, handle_newview:9629).
     * THIS handler had no sender check of any kind. It verifies the
     * PRECOMMIT CERTIFICATES against the committed authority snapshot far
     * below (:7331, O15G), and that is what stops a forged batch from
     * committing — but the SENDER was authorized by w->roster alone, at the
     * dispatch layer (nodus_witness.c:2035-2083). The roster is fed from
     * self-published DHT `nodus:pk` records whose only admission tests are
     * signature validity, expiry and dedup, with no committee filter
     * (nodus_witness_peer.c). A T3 sender identity therefore costs one
     * Dilithium keypair plus one DHT put, and such an identity reached
     * nodus_witness_v2_cert_note and the round/height bookkeeping below.
     * Bug ref: nodus/BUGS.md O15N-L4.
     *
     * WHY HERE. nodus_witness_v2_cert_note immediately below is the FIRST
     * state mutation on this path — it pools untrusted, sender-supplied
     * certificate data into w->v2_certpool and can reset that pool to a new
     * height. Gating ABOVE it means a non-committee sender leaves ZERO
     * residue: no pooled certificate, no pool reset, no sync kick, no round
     * or height bookkeeping. That is the same argument the O15C-D.4
     * consensus-version gate makes for its own placement in
     * nodus_witness.c:2093-2095.
     *
     * WHY THE CARRIED HEIGHT, NOT OUR TIP. cmt->block_height lives inside
     * the wsig-signed envelope, so it is authenticated as "this sender said
     * this height", and authority must come from the EVIDENCE rather than
     * from where the reader happens to stand — the rule handle_viewok
     * states for v->height (:9377-9380). Two nodes at different tips must
     * not reach different verdicts on identical bytes. handle_propose and
     * handle_viewchg resolve at the local tip+1 because the message they
     * judge is a proposal ABOUT the block this node would build next; a
     * COMMIT is a claim about a block that already carries its own height.
     *
     * ⚠ THIS IS NOT handle_viewok's SHAPE ON count == 0, DELIBERATELY.
     * That gate DROPS when the committee resolves empty, because it exists
     * to BOUND signature work and a roster fallback would remove exactly
     * the bound (:9401-9413). Dropping here would be a chain that cannot
     * START: the GENESIS block's COMMIT flows through this handler, and
     * pre-genesis every node resolves an empty committee at the same
     * moment — so the refusal would be simultaneous and cluster-wide, not
     * node-local. The shape mirrored here is handle_propose's three
     * outcomes (:5298-5336):
     *
     *   lc_rc != 0     a LOAD FAULT — the ABSENCE of an answer, never an
     *                  empty committee (load_committee_at_height:628-665).
     *                  Fail closed: a node that cannot name the authority
     *                  must not accept a block on the transport roster's
     *                  say-so. Cost is liveness only — nodus_witness_tick
     *                  drives sync independently (nodus_witness.c:1842,
     *                  :1987), so catch-up does not depend on the in-handler
     *                  sync kick this refusal skips.
     *   count == 0     the COMMITTED pre-genesis answer (F17 A5). Roster
     *                  membership IS the authorization, exactly as
     *                  handle_viewchg states at :8144-8145. Genesis security
     *                  comes from genesis_verify (Rule P) and honest
     *                  majority, not from committee gating.
     *   count > 0      the sender's pubkey must be in the committee.
     *
     * MEMBERSHIP, NOT RANK. handle_propose additionally ranks the sender by
     * SORTED roster position because it must identify one LEADER. A COMMIT
     * is not leader-gated — every witness broadcasts its own on reaching
     * its own precommit quorum (:7027-7029) — so requiring a rank here
     * would refuse the legitimate COMMITs of every non-leader. The
     * arrival-index hazard the sorted lookup exists to avoid
     * (nodus/BUGS.md 2026-08-04) does not arise: no index is compared to
     * anything, and nodus_witness_roster_sorted_find returns >= 0 for
     * exactly the senders nodus_witness_roster_find does (:971-987).
     *
     * THE OTHER HALF OF L4 IS NOT CLOSED HERE — see the residual note at
     * the dispatch-level wsig verify, nodus_witness.c:2047. */
    {
        int gossip_idx = nodus_witness_roster_find(&w->roster,
                                                     hdr->sender_id);
        if (gossip_idx < 0) {
            fprintf(stderr, "%s: COMMIT from unknown sender_id\n", LOG_TAG);
            return -1;
        }

        nodus_committee_member_t *committee = NULL;
        int count = 0;
        int lc_rc = load_committee_at_height_alloc(w, cmt->block_height,
                                                     &committee, &count);
        if (lc_rc != 0) {
            free(committee);
            fprintf(stderr,
                    "%s: COMMIT — CANNOT ESTABLISH THE COMMITTEE at height "
                    "%llu (rc=%d%s); refusing the commit rather than "
                    "authorizing the sender on the transport roster\n",
                    LOG_TAG, (unsigned long long)cmt->block_height, lc_rc,
                    w->db ? "" : ", chain database not open");
            return -1;
        }
        bool reject = (count > 0 &&
                       committee_find_pubkey(committee, count,
                           w->roster.witnesses[gossip_idx].pubkey) < 0);
        free(committee);
        if (reject) {
            fprintf(stderr,
                    "%s: COMMIT from non-committee sender (roster %d, "
                    "height %llu)\n", LOG_TAG, gossip_idx,
                    (unsigned long long)cmt->block_height);
            return -1;
        }
        /* else: count == 0 (genuine pre-genesis, the roster check above is
         * the authorization) or a committee member. */
    }

    /* O15O Faz 5 — RECORD, above the FIRST state mutation on this path.
     * The Faz 4 comment names that mutation as nodus_witness_v2_cert_note
     * immediately below, and the same argument places the record here: a
     * non-committee sender leaves ZERO residue, including no entry in the
     * replay cache that an honest sender would otherwise have to share
     * capacity with. */
    nonce_record(hdr->sender_id, hdr->nonce, hdr->timestamp);

    /* O15D — successor QC-certificate collection. MUST run BEFORE the
     * already-committed early-return below: on a healthy round every
     * node commits through its OWN quorum first, so by the time peers'
     * COMMIT frames arrive the round is already committed here — and
     * those frames are exactly what carries the certificates. The pair
     * is UNTRUSTED input; the pool verifies each certificate against
     * the committed authority snapshot before it can count. sender_id
     * is the snapshot voter-id derivation (SHA3-512(pubkey)[0..31],
     * nodus_identity.c:42 == vset_wire.h entry rule). */
    if (w->v2_successor && cmt->batch_count > 0 && cmt->has_v2_cert)
        nodus_witness_v2_cert_note(w, cmt->block_height, hdr->sender_id,
                                   cmt->v2_block_id, cmt->v2_cert_sig);

    /* Skip if we already committed this round */
    if (hdr->round <= w->last_committed_round) {
        QGP_LOG_DEBUG(LOG_TAG, "round %lu already committed, skipping",
                      (unsigned long)hdr->round);
        return 0;
    }

    if (cmt->batch_count > 0) {
        QGP_LOG_INFO(LOG_TAG, "received batch COMMIT for round %lu (%d TXs)",
                     (unsigned long)hdr->round, cmt->batch_count);

        /* 2026-05-02 — A2 simetri: validate leader-claimed block_height
         * mirrors handle_propose:3898-3914. Without this check the
         * follower's commit_batch defaulted to local_chain_head+1 and
         * applied wrong-height blocks during round skip → state_root
         * divergence → safety halt latched. Live cluster bug 2026-05-01
         * (US-1 halted at h=114). Bug ref:
         * project_witness_commit_height_asymmetry.
         *
         * Backward-compat: legacy peers (pre-Faz 2 wire) emit bh=0;
         * frame layer version reject (NODUS_FRAME_VERSION 0x02) should
         * already block legacy frames, but defense in depth here in
         * case CBOR-level cross-version slips through. */
        {
            /* O15O Faz 1 — this is the guard that stopped US-1's h=114
             * divergence: it refuses a COMMIT whose height is not ours.
             * A fault answering 0 would make expected_height 1, so a
             * COMMIT at height 1 would be APPLIED on a long chain. Refuse
             * before commit_batch is reached. */
            uint64_t tip = 0;
            if (nodus_witness_block_height_checked(w, &tip) != 0) {
                fprintf(stderr,
                    "%s: commit rejected — chain-height read faulted; "
                    "cannot validate the leader-claimed block_height\n",
                    LOG_TAG);
                return -1;
            }
            uint64_t expected_height = tip + 1;
            if (cmt->block_height == 0) {
                fprintf(stderr,
                    "%s: commit rejected — missing block_height "
                    "(legacy peer or malformed); sync needed\n", LOG_TAG);
                return -1;
            }
            if (cmt->block_height != expected_height) {
                /* 2026-05-02 audit M-2: silent drop for distant-future
                 * COMMITs while sync is already in-flight. Catch-up
                 * sync produces 6+ COMMIT rejects per round per peer
                 * which would otherwise log-spam during recovery. */
                if (cmt->block_height > expected_height &&
                    w->sync_state.syncing) {
                    QGP_LOG_DEBUG(LOG_TAG,
                        "commit silently dropped — sync in flight "
                        "(commit=%lu local_next=%lu)",
                        (unsigned long)cmt->block_height,
                        (unsigned long)expected_height);
                    return -1;
                }
                fprintf(stderr,
                    "%s: commit rejected — height mismatch "
                    "(commit=%llu local_next=%llu); triggering sync\n",
                    LOG_TAG,
                    (unsigned long long)cmt->block_height,
                    (unsigned long long)expected_height);
                /* Active recovery: do not wait for the next periodic
                 * sync_check tick. sync_check honors its own rate limit
                 * + IDLE phase guard so spamming this is safe. Future
                 * Faz 5 hardening: cert verify BEFORE this trigger so
                 * unauthenticated COMMITs cannot DoS the sync layer. */
                nodus_witness_sync_check(w);
                return -1;
            }
        }

        /* === Faz 3D — PRECOMMIT cert verify (C-2 defense in depth) ===
         * Verify witness signatures BEFORE state mutation. CRITICAL:
         * the existing precommit sign path (line ~4442) passes
         * round_state.tx_hash to compute_cert_preimage; that field is
         * actually tx_root (line 3977/3389: tx_hash := tx_root). The
         * "block_hash" parameter name in the verify helper is
         * misleading. Pass cmt->tx_root here to match the sign side.
         *
         * B-1 (cert preimage MUST include state_root) is a SEPARATE
         * task: it requires changing the sign side too (witnesses sign
         * full block_hash including state_root, not just tx_root) and
         * is incompatible with this current sign path. Leave as future
         * audit work. */
        if (cmt->block_height >= 2 && cmt->n_precommits > 0) {
            nodus_t3_sync_cert_t sync_certs[NODUS_T3_MAX_WITNESSES];
            uint32_t cc = (cmt->n_precommits < NODUS_T3_MAX_WITNESSES)
                        ? cmt->n_precommits : NODUS_T3_MAX_WITNESSES;
            for (uint32_t i = 0; i < cc; i++) {
                memcpy(sync_certs[i].voter_id, cmt->certs[i].voter_id,
                       NODUS_T3_WITNESS_ID_LEN);
                memcpy(sync_certs[i].signature, cmt->certs[i].signature,
                       NODUS_SIG_BYTES);
            }

            /* O15G — bind the signer pubkey source to the COMMITTED committee
             * snapshot for this block's height, not the transient transport
             * roster. Quorum comes from that snapshot (rv_quorum), never
             * w->bft_config.quorum — which at N>7 could differ from the
             * signing epoch's quorum and, before this change, silently dropped
             * a signer absent from the local roster and wedged the node. */
            uint32_t rv_quorum = 0;
            int cv = nodus_witness_verify_certs_snapshot(w, cmt->tx_root,
                                                          cmt->block_height,
                                                          w->chain_id,
                                                          sync_certs, cc,
                                                          &rv_quorum);
            if (cv < 0) {
                if (cv == NODUS_V2_NOT_YET_LINKABLE) {
                    /* The committed committee snapshot for this block's epoch
                     * is not on this node yet — we are simply behind. This is
                     * NOT proposer misbehaviour: do not blame, catch up first
                     * (mirror the height-mismatch sync trigger above).
                     *
                     * O15G §8.3 — route to the correct catch-up lane. The
                     * legacy nodus_witness_sync_check is a NO-OP on a successor
                     * (it returns early on w->v2_successor), so on a successor
                     * this NOT_YET_LINKABLE would trigger no recovery at all;
                     * drive the V2 catch-up tick instead. This only KICKS the
                     * existing sync2 driver (its own rate limits apply) — it
                     * does not change sync2 behaviour or wire. */
                    fprintf(stderr,
                        "%s: PRECOMMIT cert authority not yet available "
                        "(h=%llu) — triggering sync\n",
                        LOG_TAG, (unsigned long long)cmt->block_height);
                    if (w->v2_successor)
                        nodus_witness_v2_sync_tick(w);
                    else
                        nodus_witness_sync_check(w);
                    return -1;
                }
                if (cv == NODUS_V2_INTERNAL_FAULT) {
                    /* Local corruption / unreadable committed authority. A node
                     * that cannot know who was permitted to sign must not vote
                     * the block down — fail closed, stay silent. */
                    fprintf(stderr,
                        "%s: PRECOMMIT cert authority LOCAL FAULT "
                        "(h=%llu) — refusing to commit (fail-closed)\n",
                        LOG_TAG, (unsigned long long)cmt->block_height);
                    return -1;
                }
                fprintf(stderr,
                    "%s: PRECOMMIT cert quorum verify FAILED "
                    "(h=%llu, votes=%u, quorum=%u)\n",
                    LOG_TAG, (unsigned long long)cmt->block_height,
                    cc, rv_quorum);
                return -1;
            }
        }
        /* === end Faz 3D === */

        /* Phase 7 / Task 7.6 — multi-tx block via Phase 6 wrappers.
         *
         * Build stack-allocated mempool entries from cmt->batch_txs.
         * tx_data pointers borrow the message buffer; commit_batch does
         * not free entries. Genesis (batch_count == 1, type GENESIS)
         * dispatches to commit_genesis for chain DB bootstrap. */
        bool rmt_batch_failed;
        nodus_witness_mempool_entry_t local_entries[NODUS_W_MAX_BLOCK_TXS];
        nodus_witness_mempool_entry_t *entry_ptrs[NODUS_W_MAX_BLOCK_TXS];

        if ((uint32_t)cmt->batch_count > NODUS_W_MAX_BLOCK_TXS) {
            QGP_LOG_ERROR(LOG_TAG, "batch remote: count %d exceeds max",
                          cmt->batch_count);
            return -1;
        }

        memset(local_entries, 0, sizeof(local_entries));
        for (int bi = 0; bi < cmt->batch_count; bi++) {
            const nodus_t3_batch_tx_t *btx = &cmt->batch_txs[bi];
            nodus_witness_mempool_entry_t *e = &local_entries[bi];
            memcpy(e->tx_hash, btx->tx_hash, NODUS_T3_TX_HASH_LEN);
            e->tx_type = btx->tx_type;
            e->nullifier_count = btx->nullifier_count;
            for (int j = 0; j < btx->nullifier_count; j++) {
                if (btx->nullifiers[j])
                    memcpy(e->nullifiers[j], btx->nullifiers[j],
                           NODUS_T3_NULLIFIER_LEN);
            }
            e->tx_data = (uint8_t *)btx->tx_data;
            e->tx_len = btx->tx_len;
            /* F02 — carry client_pubkey / client_sig / fee through so the
             * verify loop below sees the same signer material as
             * handle_propose did on the leader's proposal path. */
            if (btx->client_pubkey)
                memcpy(e->client_pubkey, btx->client_pubkey, NODUS_PK_BYTES);
            if (btx->client_sig)
                memcpy(e->client_sig, btx->client_sig, NODUS_SIG_BYTES);
            e->fee = btx->fee;
            entry_ptrs[bi] = e;
        }

        /* F02 — re-verify every batch TX before applying to state.
         * handle_propose verifies on the proposal path; handle_commit's
         * fast-path (non-leader peer reaches precommit quorum and
         * broadcasts COMMIT before local_vote accumulates) previously
         * skipped verify, letting a Byzantine proposer substitute signed
         * TXs between PRECOMMIT and COMMIT. Mirrors the loop at line
         * 3562. Cost: ≤10 Dilithium5 verifies per COMMIT (bounded by
         * NODUS_W_MAX_BLOCK_TXS). */
        for (int bi = 0; bi < cmt->batch_count; bi++) {
            nodus_witness_mempool_entry_t *e = &local_entries[bi];
            char f02_reject[256];
            /* VALIDATION mode: same reason as the propose-path loop —
             * this re-verify decides whether an ALREADY-COMMITTED block
             * is applied to local state, so it must reach the identical
             * verdict on every node. A mempool-dependent reject here
             * would leave this witness behind the chain. */
            int f02_vrc = nodus_witness_verify_transaction(w,
                              e->tx_data, e->tx_len,
                              e->tx_hash, e->tx_type,
                              (const uint8_t *)e->nullifiers,
                              e->nullifier_count,
                              e->client_pubkey, e->client_sig,
                              e->fee, NODUS_WITNESS_VERIFY_VALIDATION,
                              f02_reject, sizeof(f02_reject));
            if (f02_vrc != 0) {
                QGP_LOG_ERROR(LOG_TAG,
                              "commit-path verify rejected batch TX %d: %s",
                              bi, f02_reject);
                return -1;
            }
        }

        if (w->v2_successor) {
            /* ── O15D: successor remote-COMMIT path — the same ONE
             * engine, with the sender's claimed V2 GLOBAL ROOT as the
             * C3-analog equality assertion: a divergent proposal
             * REJECTS before any commit (engine expect_* contract),
             * mirroring the legacy expected_state_root discipline. */
            nodus_v2_produce_out_t rv2out;
            int rrc = nodus_witness_v2_produce_commit(w, entry_ptrs,
                          cmt->batch_count, cmt->block_height,
                          cmt->proposal_timestamp, cmt->proposer_id,
                          cmt->state_root, &rv2out);
            rmt_batch_failed = (rrc != 0);
            if (!rmt_batch_failed) {
                /* O15H D3+D4 — same post-commit bookkeeping as the
                 * own-quorum successor path; commit_batch is not on
                 * this branch either. */
                nodus_witness_bft_after_successor_commit(w);
                /* Locally DERIVED root only (F-CONS-06 discipline). */
                memcpy(w->cached_state_root, rv2out.global_root,
                       NODUS_KEY_BYTES);
                w->cached_state_root_valid = true;

                /* O15G — circulate OUR OWN DNA.CERT.v2 certificate.
                 *
                 * produce_commit already SELF-NOTED our cert into the
                 * per-height pool (nodus_witness_v2_produce.c:564, coupled
                 * with rv2out.have_cert in the SAME success branch), so our
                 * own QC can already include us. What it does NOT do is put
                 * our cert on the wire — and this remote-COMMIT race path,
                 * unlike the own-quorum COMMIT build+broadcast (:5575-5638),
                 * previously discarded rv2out entirely below. A node that
                 * commits HERE (every just-activated joiner at an N-growth
                 * boundary, which receives the leader's COMMIT before its own
                 * precommit quorum finalizes) therefore kept its certificate
                 * to itself. With a quorum above the count of own-quorum
                 * committers, NO node ever collected enough certs and the QC
                 * never formed (v2_blocks.qc NULL on every node at the
                 * boundary height e*).
                 *
                 * Mirror the own-quorum broadcast (:5575-5583): re-carry the
                 * just-committed batch so the frame satisfies the peer-side
                 * collection gate at :5699 (batch_count > 0 && has_v2_cert)
                 * and attach our cert over the BlockID WE derived. NO STORM:
                 * we commit a given height exactly once (round guard :5704 →
                 * phase IDLE :6128; a same-height COMMIT under a different
                 * round dies at the A2 height check :5734 once the tip has
                 * advanced), so we emit our OWN cert at most once per height,
                 * and certs RECEIVED from peers are only pooled at :5699,
                 * never relayed. Heap-allocated: nodus_t3_msg_t carries
                 * certs[128] (~600 KB) and this frame already holds
                 * local_entries[]; a stack copy here risks overflow. */
                if (rv2out.have_cert) {
                    nodus_t3_msg_t *cc = calloc(1, sizeof(*cc));
                    if (cc) {
                        cc->type = NODUS_T3_COMMIT;
                        cc->txn_id = ++w->next_txn_id;
                        cc->commit = *cmt;      /* re-carry the batch */
                        cc->commit.has_v2_cert = 1;
                        memcpy(cc->commit.v2_block_id, rv2out.block_id,
                               NODUS_T3_TX_HASH_LEN);
                        memcpy(cc->commit.v2_cert_sig, rv2out.cert_sig,
                               NODUS_SIG_BYTES);
                        /* Derived global root only (F-CONS-06); the engine
                         * already asserted it equals the leader's claim. */
                        memcpy(cc->commit.state_root, rv2out.global_root,
                               NODUS_KEY_BYTES);
                        nodus_witness_bft_broadcast(w, cc);
                        free(cc);
                    } else {
                        /* A cert we cannot circulate is not a consensus
                         * fault: our block is committed and our own QC
                         * already includes us — peers may simply not reach
                         * quorum from us this round. */
                        QGP_LOG_ERROR(LOG_TAG,
                            "v2 cert broadcast alloc failed at height %llu "
                            "— cert not circulated",
                            (unsigned long long)cmt->block_height);
                    }
                }
            }
        } else if (cmt->batch_count == 1 &&
            local_entries[0].tx_type == NODUS_W_TX_GENESIS) {
            rmt_batch_failed = (nodus_witness_commit_genesis(w,
                                    local_entries[0].tx_hash,
                                    local_entries[0].tx_data,
                                    local_entries[0].tx_len,
                                    cmt->proposal_timestamp,
                                    cmt->proposer_id) != 0);
        } else {
            /* C3 fix: pass leader's state_root claim — follower must match.
             * 2026-05-02: pass cmt->block_height (already validated by
             * the A2 simetri block above) so commit_batch's TOCTOU
             * snapshot guard catches any race window. */
            rmt_batch_failed = (nodus_witness_commit_batch(w, entry_ptrs,
                                    cmt->batch_count,
                                    cmt->block_height,
                                    cmt->proposal_timestamp,
                                    cmt->proposer_id,
                                    cmt->state_root) != 0);
        }

        if (rmt_batch_failed) {
            QGP_LOG_ERROR(LOG_TAG, "batch remote commit FAILED");
            return -1;
        }
    } else {
        /* Phase 9 / Task 9.1 — legacy single-TX COMMIT path DELETED.
         * After Phase 7 every commit is batch-shaped; reject defensively. */
        QGP_LOG_ERROR(LOG_TAG, "legacy single-TX COMMIT rejected — "
                     "batch_count == 0 unsupported after Phase 7");
        return -1;
    }

    /* Store commit certificates from leader's COMMIT message.
     * O15D: successor rounds never touch the LEGACY cert table (their
     * finalization artifact is the QC V2 in v2_blocks.qc). */
    if (!w->v2_successor && cmt->n_precommits > 0) {
        uint64_t bh = nodus_witness_block_height(w);
        nodus_witness_vote_record_t votes[NODUS_T3_MAX_WITNESSES];
        for (uint32_t i = 0; i < cmt->n_precommits && i < NODUS_T3_MAX_WITNESSES; i++) {
            memcpy(votes[i].voter_id, cmt->certs[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN);
            votes[i].vote = NODUS_W_VOTE_APPROVE;
            memcpy(votes[i].signature, cmt->certs[i].signature,
                   NODUS_SIG_BYTES);
        }
        /* SEC (audit M3): nodus_witness_cert_store iterates [0, vote_count)
         * over `votes`, which the loop above filled to at most
         * NODUS_T3_MAX_WITNESSES. Passing the raw n_precommits (attacker-
         * controlled up to the CBOR item cap) would read past the stack
         * array. Clamp to the number of entries actually populated. */
        int n_certs = (cmt->n_precommits < (uint32_t)NODUS_T3_MAX_WITNESSES)
                          ? (int)cmt->n_precommits
                          : NODUS_T3_MAX_WITNESSES;
        nodus_witness_cert_store(w, bh, votes, n_certs);

        /* Phase 9 / Task 48 — liveness attendance. Credit this block's
         * proposer (cmt->proposer_id), not the precommit voters — the
         * voter set diverges per node, the proposer_id does not.
         * C4 fix: attendance is now credited inside commit_batch /
         * replay_block before finalize_block, atomic with the block
         * persist. Out-of-txn call here removed. */
    }

    /* Compute chain state_root and compare with leader's (Phase 3 / Task 10).
     *
     * F-CONS-06 — Independent state_root recompute.
     * The follower ALWAYS calls nodus_witness_merkle_compute_state_root()
     * against its own freshly-committed DB state. The leader's claimed
     * state_root (cmt->state_root, sourced from the COMMIT message) is
     * NEVER copied into w->cached_state_root; only the locally-computed
     * utxo_cksum value is retained. That guarantees a compromised leader
     * cannot propagate an invalid post-block state into follower caches
     * — even a WARN-level divergence leaves the follower with its own
     * honest state_root for every downstream consumer (cert preimages,
     * block header assembly, Merkle proof anchoring).
     * Regression: tests/test_prevote_state_root_mutation.c. */
    if (!w->v2_successor) {
        uint8_t utxo_cksum[NODUS_KEY_BYTES];
        if (nodus_witness_merkle_compute_state_root(w, utxo_cksum) == 0) {
            char hex[17];
            for (int i = 0; i < 8; i++)
                snprintf(hex + i * 2, 3, "%02x", utxo_cksum[i]);
            QGP_LOG_DEBUG(LOG_TAG, "state_root after remote commit round %llu: %s",
                         (unsigned long long)hdr->round, hex);

            /* Compare with leader's checksum (if present) */
            /* C3 fix: state_root mismatch is now caught inside
             * finalize_block (commit_batch → rollback + safety_halt
             * before this point is reached). By the time we're here the
             * block persisted ⇒ local root matches leader's. The post-
             * commit recompute below exists only to refresh cached_state_
             * root for future operations. */
            memcpy(w->cached_state_root, utxo_cksum, NODUS_KEY_BYTES);
            w->cached_state_root_valid = true;
        }
    }

    /* Update committed round */
    if (hdr->round > w->last_committed_round)
        w->last_committed_round = hdr->round;

    /* Race path: the leader can reach here when a non-leader peer hits
     * precommit quorum and broadcasts COMMIT before the leader's own
     * handle_vote accumulates its local quorum. In that case the leader's
     * round_state still holds batch_entries with client_conn / forwarder_id
     * routing info, but handle_vote's reply loop will never run (handle_vote
     * bails once phase != PRECOMMIT). Emit replies here so forwarded client
     * spends don't silently drop their w_fwd_rsp. Helper is idempotent.
     *
     * handle_commit calls commit_batch with stack-allocated local_entries
     * (built from cmt->batch_txs), so commit_batch populates
     * committed_block_height / committed_tx_index on THOSE stack entries,
     * not on round_state.batch_entries. Copy the coordinates across so the
     * helper emits the correct block number / tx index in spend_result and
     * w_fwd_rsp; otherwise the forwarder path still sees zeros. */
    if (w->round_state.round == hdr->round &&
        w->round_state.batch_count > 0) {
        fprintf(stderr, "%s: remote-COMMIT race — emitting replies for own "
                "round %lu from handle_commit path\n",
                LOG_TAG, (unsigned long)hdr->round);
        uint64_t committed_bh = nodus_witness_block_height(w);
        for (int bi = 0; bi < w->round_state.batch_count; bi++) {
            if (w->round_state.batch_entries[bi]) {
                w->round_state.batch_entries[bi]->committed_block_height =
                    committed_bh;
                w->round_state.batch_entries[bi]->committed_tx_index =
                    (uint32_t)bi;
            }
        }
        /* Reached only after the remote commit landed locally — a failed
         * remote commit returned -1 above, before this point. */
        bft_emit_batch_replies(w, DNAC_STATUS_APPROVED, NULL);
    }
    if (w->round_state.round == hdr->round) {
        w->round_state.phase = NODUS_W_PHASE_IDLE;
        w->round_state.client_conn = NULL;
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * View change
 * ════════════════════════════════════════════════════════════════════ */

/* S3 — the ONE owner of nodus_witness_vc_record_t::prepared::sigs.
 *
 * Every site that used to `memset` a view-change record calls this
 * instead; a bare memset would drop the heap pointer on the floor. The
 * post-condition is the same as the old memset's: a fully zeroed record
 * with has_prepared == false, n_sigs == 0 and sigs == NULL.
 *
 * Declared in nodus_witness.h so nodus_witness_close can drain the array
 * at shutdown. NULL-safe; idempotent (free(NULL) is a no-op and the
 * pointer is re-nulled by the memset). */
void nodus_witness_vc_record_clear(nodus_witness_vc_record_t *vc) {
    if (!vc) return;
    free(vc->prepared.sigs);
    memset(vc, 0, sizeof(*vc));
}

/* Allocate a view-change record's prepared-sig array (S3).
 *
 * Replaces the in-struct array the copy loops used to write into. Any
 * previous allocation on the slot is released first, so a slot can be
 * re-filled without leaking. `*n_io` is clamped IN PLACE to
 * DNAC_MAX_ACTIVE_VALIDATORS so the caller's copy loop and the array
 * agree on the bound. `*n_io == 0` leaves the slot with sigs == NULL /
 * n_sigs == 0.
 *
 * The caller fills the entries field-by-field: the sources (the
 * anonymous struct inside w->last_prepared, and nodus_t3_viewchg_t's
 * wire array) have the same LAYOUT but are distinct TYPES, so a bulk
 * memcpy between them would be type punning rather than a copy.
 *
 * @return 0 on success, -1 on allocation failure (slot left empty and
 *         has_prepared cleared — a cert we cannot store is a cert we
 *         must not claim to hold). */
static int vc_record_alloc_sigs(nodus_witness_vc_record_t *vc,
                                  uint32_t *n_io) {
    if (!vc || !n_io) return -1;
    free(vc->prepared.sigs);
    vc->prepared.sigs   = NULL;
    vc->prepared.n_sigs = 0;

    if (*n_io > (uint32_t)DNAC_MAX_ACTIVE_VALIDATORS)
        *n_io = (uint32_t)DNAC_MAX_ACTIVE_VALIDATORS;
    if (*n_io == 0) return 0;

    nodus_witness_prepared_sig_t *arr = calloc((size_t)*n_io, sizeof(*arr));
    if (!arr) {
        vc->prepared.has_prepared = false;
        *n_io = 0;
        return -1;
    }
    vc->prepared.sigs   = arr;
    vc->prepared.n_sigs = *n_io;
    return 0;
}

/* Forward decl — defined beside handle_viewchg below (O15C-C D1). */
static int bft_vc_check_quorum(nodus_witness_t *w);

/* O15H D5b — the f+1 threshold at which we JOIN a view we did not ask
 * for, DERIVED FROM THE QUORUM IN FORCE.
 *
 * f is deliberately NOT read from bft_config.f_tolerance. That field is
 * a second, separately-written copy of the same fact, and a caller that
 * sets quorum without it (several test fixtures do) would silently get
 * f+1 == 1 — a threshold that turns ONE Byzantine message into a
 * cluster-wide broadcast, which is the exact hazard this threshold
 * exists to prevent. Deriving it from `quorum` means the number can
 * never disagree with the quorum every other decision on this path
 * already uses.
 *
 * Exact across the whole supported range, because quorum is
 * dna_bft_quorum(n) = (2n)/3 + 1 and f_tolerance is (n-1)/3:
 *   n=4   quorum 3  → (3-1)/2  = 1  = f     n=7   quorum 5  → 2  = f
 *   n=20  quorum 14 → (14-1)/2 = 6  = f     n=128 quorum 86 → 42 = f
 *
 * The floor of 2 is the anti-amplification backstop: below quorum 3 the
 * formula degenerates to 1, and one message must never be able to make
 * this node speak. A cluster that small simply falls back to voting at
 * its own timeout, which is the pre-O15H behaviour and always correct. */
static uint32_t bft_vc_join_threshold(const nodus_witness_t *w) {
    uint32_t q = w ? w->bft_config.quorum : 0;
    uint32_t t = (q > 1) ? ((q - 1) / 2) + 1 : 0;
    return (t < 2) ? 2 : t;
}

/* ── O15H D9 — PER-TARGET TALLY OVER PER-VOTER RECORDS ──────────────
 *
 * THE DEFECT THIS REPLACES. `view_changes[]` used to be "the votes for
 * the ONE target we are currently chasing", and any single VIEW_CHANGE
 * naming a higher view REPLACED that target and cleared the array. One
 * Byzantine committee member could therefore keep every honest node's
 * tally at zero forever, simply by announcing target+1 again whenever
 * the honest nodes started to accumulate — a liveness attack costing one
 * message per reset, with no honest node able to notice.
 *
 * THE NEW INVARIANT: one record per VOTER, holding that voter's HIGHEST
 * requested target. A voter can move its own opinion and nothing else;
 * it cannot evict, reset or outnumber anyone. The array is bounded by
 * the committee size for free, because a repeat sender updates its own
 * slot instead of taking another.
 *
 * "The tally" is then a QUESTION asked of that set — how many voters
 * currently sit at target T — rather than a counter something can zero.
 * Adoption needs f+1 voters at T (the same Castro-Liskov condition that
 * governs when we SPEAK), and completion needs a quorum at T.
 *
 * ⚠ THE SAFETY PROPERTY THE OLD WIPE PROVIDED IS PRESERVED, DELIBERATELY
 * AND ELSEWHERE. Clearing the array on a target change existed so a
 * prepared certificate attached to a LOWER target could not be counted
 * in a HIGHER target's C5 selection. Records now survive a target
 * change, so every C5 consumer FILTERS on target_view ==
 * view_change_target instead — see
 * nodus_witness_bft_bind_reproposal_from_view_changes and the NEW_VIEW
 * source scan. Same guarantee, without a mechanism an attacker can
 * trigger. */

/* Slot holding `voter_id`, or -1. */
static int bft_vc_find_voter(const nodus_witness_t *w, const uint8_t *voter_id) {
    for (int i = 0; i < w->view_change_count; i++) {
        if (memcmp(w->view_changes[i].voter_id, voter_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return i;
    }
    return -1;
}

/* How many voters currently sit at `target`. */
static uint32_t bft_vc_tally(const nodus_witness_t *w, uint32_t target) {
    uint32_t n = 0;
    for (int i = 0; i < w->view_change_count; i++)
        if (w->view_changes[i].target_view == target) n++;
    return n;
}

/* The highest target above `current_view` that f+1 voters back, or 0 if
 * none does. Scanning the records rather than tracking a "pending view"
 * keeps ONE source of truth for what the cluster is asking for. */
static uint32_t bft_vc_best_supported_target(const nodus_witness_t *w) {
    uint32_t thr = bft_vc_join_threshold(w);
    uint32_t best = 0;
    for (int i = 0; i < w->view_change_count; i++) {
        uint32_t t = w->view_changes[i].target_view;
        if (t <= w->current_view || t <= best) continue;
        if (bft_vc_tally(w, t) >= thr) best = t;
    }
    return best;
}

/* O15C-D.3 — record OUR OWN view-change vote, carrying our own
 * `last_prepared`, into `view_changes[]`.
 *
 * APPEND, never clobber: on the join path peer votes already occupy the
 * slots below `view_change_count`. Idempotent — once our record is
 * present a second call does nothing.
 *
 * ⚠ WHY THIS IS A SHARED HELPER (the O15C-D.3 safety defect). This block
 * used to live only inside initiate_view_change. A node that reached
 * view-change quorum from PEER messages before its own round timer fired
 * never ran it, and afterwards initiate_view_change targets
 * `current_view + 1` — so the node's own prepared certificate never
 * entered its own decision. Measured on the production handlers with
 * real signatures: a node that had PREPARED a value entered the new view
 * with own_record=0, with_cert=0 and its C5 gate UNARMED at that very
 * height. Since nothing else consults `last_prepared` at propose/vote
 * time, it would then vote a conflicting value at a height it prepared —
 * exactly the refusal quorum intersection relies on, i.e. a fork.
 * `bft_vc_check_quorum` now calls this too, so a node's own evidence can
 * never be missing from its own decision on either path. */
static void bft_self_record_view_change(nodus_witness_t *w) {
    if (!w) return;

    /* O15H D9 — UPSERT, not append-if-absent. Under per-voter records
     * this node keeps ONE slot, and escalation moves that slot's target
     * rather than adding a second opinion from the same voter. The old
     * "already present → return" would have frozen our record at the
     * FIRST target we ever voted for, so every later escalation would
     * have counted us at a view we had abandoned. */
    int slot = bft_vc_find_voter(w, w->my_id);
    if (slot >= 0) {
        if (w->view_changes[slot].target_view == w->view_change_target)
            return;                    /* already recorded at this target */
    } else {
        if (w->view_change_count >= DNAC_MAX_ACTIVE_VALIDATORS) return;
        slot = w->view_change_count++;
    }
    /* S3: clear, not memset — the slot may still own a sigs allocation
     * from a previous view change. */
    nodus_witness_vc_record_clear(&w->view_changes[slot]);
    memcpy(w->view_changes[slot].voter_id, w->my_id,
           NODUS_T3_WITNESS_ID_LEN);
    w->view_changes[slot].target_view = w->view_change_target;
    w->view_changes[slot].last_committed_round = w->last_committed_round;

    if (w->last_prepared.present) {
        w->view_changes[slot].prepared.has_prepared = true;
        w->view_changes[slot].prepared.height = w->last_prepared.height;
        w->view_changes[slot].prepared.view = w->last_prepared.view;
        memcpy(w->view_changes[slot].prepared.tx_hash,
               w->last_prepared.tx_hash, NODUS_T3_TX_HASH_LEN);
        uint32_t stored = w->last_prepared.n_sigs;
        if (vc_record_alloc_sigs(&w->view_changes[slot], &stored) != 0) {
            fprintf(stderr, "%s: view_change: prepared-sig alloc failed — "
                    "self-record carries no prepared cert\n", LOG_TAG);
        } else {
            for (uint32_t i = 0; i < stored; i++) {
                memcpy(w->view_changes[slot].prepared.sigs[i].voter_id,
                       w->last_prepared.sigs[i].voter_id,
                       NODUS_T3_WITNESS_ID_LEN);
                memcpy(w->view_changes[slot].prepared.sigs[i].signature,
                       w->last_prepared.sigs[i].signature,
                       NODUS_SIG_BYTES);
            }
        }
    }
    /* O15H D9 — the slot was allocated above (a fresh append bumps the
     * count there); an upsert into our EXISTING slot must not. */
}

int nodus_witness_bft_initiate_view_change(nodus_witness_t *w) {
    if (!w) return -1;

    /* O15C-C D1 — a node that already broadcast + self-recorded its own
     * VIEW_CHANGE vote for the current target has nothing left to do.
     * But a node whose view_change_in_progress was set by RECEIVING a
     * peer's VIEW_CHANGE (the handle_viewchg join path) has NOT voted
     * yet: the old unconditional in_progress early-return here silenced
     * every joiner at its own round timeout — in the 2026-08-19
     * rehearsal round 20 that muted six of seven voters and made
     * view-change quorum (5) structurally unreachable (observed 1/5 on
     * every node). */
    if (w->view_change_in_progress && w->view_change_voted)
        return 0;

    if (!w->view_change_in_progress) {
        w->view_change_in_progress = true;
        w->view_change_target = w->current_view + 1;
        /* O15H D9 — records are NOT cleared. They belong to other
         * voters, each describing that voter's own current target; our
         * starting a view change says nothing about theirs. The tally is
         * per-target, so records at other targets simply do not count
         * toward this one. */
    }

    /* P1(a) — ANCHOR THE VIEW CHANGE TO A HEIGHT THAT IS STILL OPEN.
     *
     * `round_state.block_height` is written on round ENTRY only
     * (handle_propose :4636, and the leader's own start path), and the
     * commit reset at :6254-6257 leaves the finished round's height in
     * place when it returns the phase to IDLE. So an IDLE node's height
     * field is the height it LAST worked on — i.e. <= the committed tip.
     *
     * FIVE callers reach this function, and they split two ways. TWO run
     * from inside a LIVE round and already hold tip+1, so for them this
     * block is a no-op: the view-change escalation (:9562, whose phase is
     * already NODUS_W_PHASE_VIEW_CHANGE) and the own-round-timeout entry
     * (:9626). THREE can enter straight from IDLE carrying that stale
     * height — the f+1 join at :7669, reached from handle_viewchg, which
     * has no phase gate, and the two IDLE deadmen, P2 at :9313 and P3 at
     * :9442. Without this normalization the P1(b) release below would
     * read `tip >= block_height` as true on the very next tick and kill
     * the entry before it could vote; the joiner would be silenced
     * exactly as O15C-C D1 silenced it, one mechanism further along.
     *
     * A view change is about the NEXT block, so tip+1 is what the field
     * means here. Idempotent by construction: a round already anchored
     * at tip+1 fails the `<=` and is left byte-identical, so the two
     * in-round callers keep their existing behaviour. It can only ever
     * RAISE a stale value — handle_propose validates an incoming
     * proposal's height against the same local next-height, so no
     * legitimate round is ever anchored above tip+1 for this to lower. */
    {
        /* O15O Faz 1 — THE CLAMP IS SKIPPED ON A FAULT, not applied
         * against a fallback. The normalization above is only sound
         * because `committed_tip` is the real tip; a fault answering 0
         * would drive `round_state.block_height` DOWN to 1 on any chain
         * past height 1 — and this field is what every cert_sig preimage
         * in the resulting view change is signed over. Leaving the field
         * alone is strictly safer: the value already there is a height
         * this node genuinely worked on, and the P1(b) release below is
         * itself guarded (it reads the tip through the fail-open
         * accessor, where a bogus 0 cannot satisfy `0 >= block_height`
         * for a non-zero height). */
        uint64_t committed_tip = 0;
        if (nodus_witness_block_height_checked(w, &committed_tip) != 0) {
            fprintf(stderr,
                    "%s: view change — chain-height read faulted; leaving "
                    "the round anchor at %llu rather than clamping it "
                    "against an unknown tip\n", LOG_TAG,
                    (unsigned long long)w->round_state.block_height);
        } else if (w->round_state.block_height <= committed_tip) {
            w->round_state.block_height = committed_tip + 1;
        }
    }

    /* O15M — STAMP THE PHASE CLOCK WHERE THE PHASE CHANGES.
     *
     * THE INVARIANT: while `round_state.phase` is
     * NODUS_W_PHASE_VIEW_CHANGE, `phase_start_time` is the age of the
     * CURRENT target's window — never a window inherited from a round
     * that already ended. The two writes belong together, so they sit
     * together.
     *
     * WHY HERE AND NOT AT THE CALL SITES. Of the five callers, four
     * stamp the clock by hand in the same block just before calling —
     * P2 at :9312, P3 at :9441, the escalation at :9555 and the own
     * round timeout at :9615 — and the f+1 join at :7669 does not. A
     * node pulled into a view change by that join therefore measured its
     * budget from whatever `phase_start_time` its LAST round left
     * behind: the field is written at round entry only (:4216 leader,
     * :5063 follower, :5916 on PREVOTE quorum), and the round-equality
     * reset in handle_commit (:6984-6987) returns the phase to IDLE
     * without touching it. That leftover stamp has no bound on its age,
     * and it only has to exceed viewchg_timeout_ms (10 s) for the
     * escalation at :9512 to fire on the very next tick — which for a
     * node whose previous round ran its full round_timeout_ms (15 s,
     * nodus_types.h:161-162) it already does. That is the O15H D2 shape,
     * re-entered through a new door.
     *
     * WHY AFTER THE EARLY RETURN AT :7226, NOT BEFORE IT. Past that
     * return the call is genuinely new work — a first vote, or a new
     * target — so restarting the window is what the invariant asks for.
     * Stamping BEFORE the return would let a REPEATED call restart an
     * in-flight window and starve the escalation at :9512 forever, since
     * that branch is the only thing that ever gives up on a target.
     * HONESTLY: no current caller can do that. The escalation forces
     * `view_change_voted` false first (:9553) and the f+1 join is gated
     * on it being false (:7656); P2 and P3 both live inside the IDLE
     * branch of nodus_witness_bft_check_timeout and this call moves the
     * phase out of IDLE, so neither can re-enter until something returns
     * it there (P2 additionally spends its deadline at :9311, P3
     * re-stamps its window at :9419). The placement is therefore a
     * defensive choice against a FUTURE caller, not a fix for a live
     * path.
     *
     * WHAT THIS DOES NOT FIX, and why the four hand-stamps are KEPT
     * rather than deleted as redundant. When the early return DOES fire
     * — the flags left true by a dead episode, which :6984-6987 produces
     * because it resets the phase and writes NEITHER flag — this
     * function returns without transitioning, without self-recording and
     * without re-broadcasting. Nothing here runs. In that state the
     * caller's own stamp is the ONLY thing keeping the escalation's
     * budget honest, and the own-round-timeout site at :9615 is the one
     * that reaches it. */
    w->round_state.phase_start_time = time_ms();
    w->round_state.phase = NODUS_W_PHASE_VIEW_CHANGE;

    /* Record our own view-change vote, carrying our own last_prepared.
     * O15C-D.3 — one shared implementation; bft_vc_check_quorum calls the
     * same helper so the join path cannot omit our evidence. */
    bft_self_record_view_change(w);

    /* Build and broadcast VIEW_CHANGE */
    nodus_t3_msg_t vc;
    memset(&vc, 0, sizeof(vc));
    vc.type = NODUS_T3_VIEWCHG;
    vc.txn_id = ++w->next_txn_id;
    vc.viewchg.new_view = w->view_change_target;
    vc.viewchg.last_committed_round = w->last_committed_round;
    /* C5 — attach our own last_prepared (if any) to the outbound
     * VIEW_CHANGE so peers can learn about the highest prepared value
     * we saw. Absent prepared leaves has_prepared=false → 2-key wire. */
    if (w->last_prepared.present) {
        vc.viewchg.has_prepared = true;
        vc.viewchg.prepared_height = w->last_prepared.height;
        vc.viewchg.prepared_view = w->last_prepared.view;
        memcpy(vc.viewchg.prepared_tx_hash, w->last_prepared.tx_hash,
               NODUS_T3_TX_HASH_LEN);
        vc.viewchg.prepared_n_sigs = w->last_prepared.n_sigs;
        for (uint32_t i = 0; i < w->last_prepared.n_sigs &&
                              i < NODUS_T3_MAX_WITNESSES; i++) {
            memcpy(vc.viewchg.prepared_sigs[i].voter_id,
                   w->last_prepared.sigs[i].voter_id,
                   NODUS_T3_WITNESS_ID_LEN);
            memcpy(vc.viewchg.prepared_sigs[i].signature,
                   w->last_prepared.sigs[i].signature,
                   NODUS_SIG_BYTES);
        }
    }

    int sent = nodus_witness_bft_broadcast(w, &vc);
    w->view_change_voted = true;

    fprintf(stderr, "%s: initiated view change to view %u (sent=%d)\n",
            LOG_TAG, w->view_change_target, sent);

    /* O15C-C D1 — our self-record can be the vote that completes the
     * quorum (every peer already sent theirs before our timeout fired). */
    return bft_vc_check_quorum(w);
}

int nodus_witness_bft_handle_viewchg(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    /* C3 fix: refuse all BFT participation once safety_halt is latched. */
    if (w->safety_halt) return -1;

    const nodus_t3_viewchg_t *vc = &msg->viewchg;
    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay CHECK — pure, records nothing. The matching nonce_record is
     * below the committee gate (O15O Faz 5). The D9 note further down,
     * which leans on "replayed old messages are already refused by
     * is_replay() at the top of this function", still holds: the frames
     * D9 is about are VIEW_CHANGEs from committee members, and those ARE
     * recorded — below the gate, before the upsert D9 describes. */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    /* F17 A3 — VIEW_CHANGE sender must be a committee member. F17 A5
     * bootstrap — pre-genesis (no committee), gossip_idx >= 0 is
     * sufficient authorization. */
    int gossip_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (gossip_idx < 0) return -1;
    const uint8_t *sender_pk = w->roster.witnesses[gossip_idx].pubkey;
    {
        /* O15O Faz 1 — the height that selects the committee this
         * VIEW_CHANGE's sender must belong to. A fault answering 0 would
         * authorize the sender against the height-1 committee, which is
         * the same class of hole the committee-load fault below closes:
         * driving this node's view rotation from the wrong authority.
         * Refuse; the cost is liveness only, identically argued. */
        uint64_t tip = 0;
        if (nodus_witness_block_height_checked(w, &tip) != 0) {
            fprintf(stderr,
                    "%s: VIEW_CHANGE — chain-height read faulted; refusing "
                    "the view change rather than authorizing the sender "
                    "against the committee at height 1\n", LOG_TAG);
            return -1;
        }
        uint64_t next_bh = tip + 1;
        nodus_committee_member_t *committee = NULL;
        int count = 0;
        bool reject = false;
        int lc_rc = load_committee_at_height_alloc(w, next_bh, &committee,
                                                     &count);
        if (lc_rc != 0) {
            /* ── O15L Faz 4 / DG-4 / G4 — THE WORST SHAPE OF THE FIVE,
             * because the fault used to leave `reject` at its false
             * initialiser: a committee-load failure did not fall back to
             * anything, it ACCEPTED. Any node on the transport roster
             * could then drive this node's view rotation.
             *
             * Fail closed, mirroring the shipped VOTE gate (O15J Block
             * 2A). Cost is liveness only: declining a VIEW_CHANGE leaves
             * this node in its old view, where its persisted
             * last_prepared lock still refuses conflicting values. */
            free(committee);
            fprintf(stderr,
                    "%s: VIEW_CHANGE — CANNOT ESTABLISH THE COMMITTEE at "
                    "height %llu (rc=%d%s); refusing the view change "
                    "rather than accepting it on the transport roster\n",
                    LOG_TAG, (unsigned long long)next_bh, lc_rc,
                    w->db ? "" : ", chain database not open");
            return -1;
        }
        if (count > 0 &&
            committee_find_pubkey(committee, count, sender_pk) < 0) {
            reject = true;
        }
        free(committee);
        if (reject) {
            fprintf(stderr,
                    "%s: VIEW_CHANGE from non-committee sender\n", LOG_TAG);
            return -1;
        }
        /* else: rc == 0 with count == 0 (genuine pre-genesis, the gossip
         * check above is the authorization) or a committee member. */
    }

    /* O15O Faz 5 — RECORD, below the committee gate and above the D9
     * upsert, which is this handler's first state mutation. A sender that
     * is not in the committee governing our next height therefore takes
     * no capacity from the ones that are. */
    nonce_record(hdr->sender_id, hdr->nonce, hdr->timestamp);

    /* Must be for a future view */
    if (vc->new_view <= w->current_view)
        return 0;

    /* O15H D9 — UPSERT THIS VOTER'S RECORD; adoption is decided AFTER,
     * from the record set, not by this one message.
     *
     * A voter already holding a slot updates it (and only if the new
     * target is strictly higher — a voter may raise its own ask, never
     * lower it, so a replayed older message changes nothing). A new
     * voter takes a free slot. Either way no other voter's record is
     * touched, which is precisely what the old "clear the array"
     * adoption made impossible. */
    int slot = bft_vc_find_voter(w, hdr->sender_id);
    if (slot >= 0) {
        /* A voter's record holds its LATEST stated target, in whichever
         * direction it moved.
         *
         * ⚠ IT USED TO BE "may raise, never lower", and that single word
         * deadlocked the cluster. D9 deliberately lets a node that ran
         * ahead FOLLOW the f+1-supported target back DOWN — and when it
         * did, every peer discarded the announcement as stale, kept
         * counting it at the target it had abandoned, and the tally at
         * the real target could never reach quorum. Two rules of the
         * same design contradicting each other. Reproduced by
         * test_newview_convergence with k=2 sender-scoped VIEW_CHANGE
         * drops, where the margin is exactly zero (4 peers + self = the
         * quorum of 5) so one miscounted voter is enough:
         * "chain did not advance past 1 within 240 s".
         *
         * Taking the latest costs nothing in safety. Replayed old
         * messages are already refused by is_replay() at the top of this
         * function, VIEW_CHANGE rides the per-peer TCP witness mesh so a
         * sender's own messages cannot overtake each other, and a voter
         * that flaps only ever moves its OWN slot by one — it can no
         * more reset a tally than it could before. */
        if (vc->new_view == w->view_changes[slot].target_view)
            return 0;                  /* duplicate — nothing to record */
        /* Re-used slot: release any prepared cert it holds. The record
         * is about to describe a DIFFERENT target, and a cert admitted
         * for the old one must not survive under the new. */
        nodus_witness_vc_record_clear(&w->view_changes[slot]);
    } else if (w->view_change_count < DNAC_MAX_ACTIVE_VALIDATORS) {
        /* S3: the slot bound is the ARRAY capacity — view-change quorum
         * is dna_bft_quorum(active_set_size), which at n = 128 is 86, so
         * a DNAC_COMMITTEE_SIZE bound would silently drop the votes that
         * reach quorum on a large active set. One record per voter keeps
         * the occupancy bounded by the committee regardless. */
        slot = w->view_change_count++;
        nodus_witness_vc_record_clear(&w->view_changes[slot]);
    } else {
        fprintf(stderr, "%s: VIEW_CHANGE record array full (%d) — "
                "dropping vote from gossip %d\n", LOG_TAG,
                w->view_change_count, gossip_idx);
        return 0;
    }

    {
        memcpy(w->view_changes[slot].voter_id,
               hdr->sender_id, NODUS_T3_WITNESS_ID_LEN);
        w->view_changes[slot].target_view = vc->new_view;
        w->view_changes[slot].last_committed_round =
            vc->last_committed_round;

        /* C5 — verify + store the incoming prepared cert. Each sig in
         * vc->prepared_sigs is verified against the PREPARED preimage
         * built from (prepared_view, prepared_height, prepared_tx_hash)
         * using the voter's committee pubkey. We only accept the cert
         * as "prepared" if at least 2f+1 sigs verify. Partial verify
         * (< quorum) is treated as "no prepared" — the vote still
         * counts toward view-change quorum, just not as prepared. */
        if (vc->has_prepared) {
            /* O15H C5 — ONE VERIFIER, not two.
             *
             * This block used to carry its OWN copy of the resolve +
             * verify + count loop, and the copy had drifted from the one
             * in nodus_witness_bft_verify_prepared_cert: it had NO
             * duplicate-voter guard, so a single valid signature
             * repeated quorum-many times "proved" a certificate exactly
             * one validator had signed. Two implementations of one
             * safety rule is how that happens, so there is now one. The
             * shared verifier also carries the C5 authority fix
             * (membership AND threshold from the committee governing
             * prepared_height).
             *
             * The wire array is already nodus_t3_cert_entry_t, the
             * verifier's parameter type — no conversion, no punning. */
            uint32_t n_sigs = vc->prepared_n_sigs;
            if (n_sigs > NODUS_T3_MAX_WITNESSES)
                n_sigs = NODUS_T3_MAX_WITNESSES;
            {
                bool cert_ok = nodus_witness_bft_verify_prepared_cert(
                                   w, vc->prepared_height, vc->prepared_view,
                                   vc->prepared_tx_hash, vc->prepared_sigs,
                                   n_sigs);
                if (cert_ok) {
                    /* Cert is quorum-valid; store full prepared data so
                     * the leader scan can consider this entry.
                     *
                     * S3: sigs is heap-owned and sized to the cert, so the
                     * old DNAC_COMMITTEE_SIZE truncation is gone — keeping
                     * only 7 of a 128-member set's 86-sig quorum would
                     * have made the stored cert unverifiable downstream.
                     * The remaining clamp is the release ceiling, applied
                     * inside vc_record_alloc_sigs. */
                    uint32_t stored = n_sigs;
                    w->view_changes[slot].prepared.has_prepared = true;
                    w->view_changes[slot].prepared.height =
                        vc->prepared_height;
                    w->view_changes[slot].prepared.view = vc->prepared_view;
                    memcpy(w->view_changes[slot].prepared.tx_hash,
                           vc->prepared_tx_hash, NODUS_T3_TX_HASH_LEN);
                    if (vc_record_alloc_sigs(&w->view_changes[slot],
                                               &stored) != 0) {
                        fprintf(stderr, "%s: C5 prepared-sig alloc failed — "
                                "cert from gossip %d dropped\n",
                                LOG_TAG, gossip_idx);
                    } else {
                        for (uint32_t si = 0; si < stored; si++) {
                            memcpy(w->view_changes[slot].prepared.sigs[si].voter_id,
                                   vc->prepared_sigs[si].voter_id,
                                   NODUS_T3_WITNESS_ID_LEN);
                            memcpy(w->view_changes[slot].prepared.sigs[si].signature,
                                   vc->prepared_sigs[si].signature,
                                   NODUS_SIG_BYTES);
                        }
                        fprintf(stderr, "%s: C5 accepted prepared cert from "
                                "gossip %d (height=%llu view=%u sigs=%u)\n",
                                LOG_TAG, gossip_idx,
                                (unsigned long long)vc->prepared_height,
                                vc->prepared_view, n_sigs);
                    }
                } else {
                    /* The verifier already logged verified/required/
                     * committee size — a second, less informed line here
                     * would only invite the two to disagree. The vote
                     * still counts toward view-change quorum; it just
                     * carries no prepared value. */
                    fprintf(stderr, "%s: C5 prepared cert from gossip %d "
                            "not accepted — vote counts, cert ignored\n",
                            LOG_TAG, gossip_idx);
                }
            }
        }

    }

    /* O15H D9 — ADOPTION IS A CONCLUSION FROM THE RECORD SET.
     *
     * Raise our target to the highest view f+1 voters actually back. One
     * message can no longer move it, so the reset attack has nothing to
     * pull. Everything the old adoption block did on a target change
     * still happens here — the D2 clock restart and re-arming our vote —
     * but only once the cluster, not one peer, has asked. */
    {
        uint32_t supported = bft_vc_best_supported_target(w);
        /* FOLLOW f+1, IN EITHER DIRECTION. Adopting only UPWARD would
         * strand a node that escalated on its own timer a step ahead of
         * everyone else: its target can never come back down, the f+1
         * sitting one view below can never pull it in, and it waits out
         * every window alone. `bft_vc_best_supported_target` returns the
         * HIGHEST target f+1 voters back, which is a deterministic
         * tie-break — every node computing it over the same records
         * picks the same view — so following it converges instead of
         * oscillating. current_view is untouched here, so nothing about
         * leader election or safety rides on this. */
        if (supported > w->current_view &&
            (supported != w->view_change_target ||
             !w->view_change_in_progress)) {
            w->view_change_in_progress = true;
            w->view_change_target = supported;
            /* O15H D2 (second half) — a new target restarts the window;
             * inheriting the abandoned target's elapsed time would leave
             * only a remainder in which to gather a full quorum. Only
             * while we are in the view-change phase: a node still in
             * PREVOTE/PRECOMMIT must keep its ROUND clock so its own
             * round timeout still fires. */
            if (w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE)
                w->round_state.phase_start_time = time_ms();
            /* O15C-C D1 — any vote we broadcast was for the OLD target;
             * the next initiate must be able to vote again. */
            w->view_change_voted = false;
        }
    }

    fprintf(stderr, "%s: VIEW_CHANGE from gossip %d: view %u "
            "(target %u: %u/%u, records %d)\n",
            LOG_TAG, gossip_idx, vc->new_view, w->view_change_target,
            bft_vc_tally(w, w->view_change_target),
            w->bft_config.quorum, w->view_change_count);

    /* O15H D5b — PBFT's f+1 RULE: once f+1 DISTINCT validators have
     * asked for a view we have not voted for, join them NOW instead of
     * waiting for our own timeout.
     *
     * This is what makes D5's escalation converge. Without it a node
     * that ADOPTED a higher target from a peer (the block above) records
     * the peer's vote, wipes its tally and restarts its clock — but
     * never casts its OWN vote at that target until its own timer
     * fires, and by then the escalation has moved the nodes that DID
     * vote on to the next target. The cluster leapfrogs, one step out of
     * phase, and no target ever accumulates a quorum: precisely the
     * churn D5 exists to end, re-introduced one level up.
     *
     * f+1 rather than 1 is the point. Adopting a TARGET from a single
     * message is the behaviour this function already had; BROADCASTING
     * on a single message would let one Byzantine node turn its own
     * message into N, every time it chose to. f+1 guarantees at least
     * one HONEST validator genuinely wants this view, which is the
     * classical Castro-Liskov condition for joining one.
     *
     * initiate_view_change self-records, broadcasts, marks us voted and
     * runs the quorum check itself — so it REPLACES the tail call rather
     * than preceding it. Calling both would let a completed view change
     * run its completion twice (bft_vc_check_quorum does not re-guard on
     * view_change_in_progress) and broadcast two NEW_VIEWs.
     *
     * O15H D9 CLOSED the companion hole: the tally is now counted PER
     * TARGET over per-voter records, so a Byzantine node can move only
     * its own record and can neither reset the count nor drag the target
     * on its own. The threshold below is therefore asked of a set that
     * nothing can zero. */
    uint32_t join_threshold = bft_vc_join_threshold(w);
    if (!w->view_change_voted && w->view_change_target > w->current_view &&
        bft_vc_tally(w, w->view_change_target) >= join_threshold) {
        fprintf(stderr, "%s: f+1 (%u >= %u) peers want view %u — voting "
                "now instead of waiting for our own timeout\n", LOG_TAG,
                bft_vc_tally(w, w->view_change_target), join_threshold,
                w->view_change_target);
        O15H_DIAG(w, "vc_enter_f1", hdr->sender_id,
                  w->round_state.block_height, w->current_view,
                  w->view_change_target, w->round_state.phase,
                  w->round_state.phase_start_time,
                  time_ms() - w->round_state.phase_start_time, "VIEWCHG", 0,
                  bft_vc_tally(w, w->view_change_target), join_threshold,
                  "f+1 adoption pulled us into VIEW_CHANGE");
        return nodus_witness_bft_initiate_view_change(w);
    }

    /* Check for quorum (shared with initiate_view_change — O15C-C D1:
     * the initiator's own self-record can complete the quorum too). */
    return bft_vc_check_quorum(w);
}

/* ════════════════════════════════════════════════════════════════════
 * O15N Faz 2C2 — THE VIEW COUNTER MOVES ONLY ON A VERIFIED PROOF
 *
 * WHAT CHANGED. `w->current_view` had four writers in this file and only
 * ONE was backed by a proven majority: a PROPOSE copied the leader's
 * claimed view unconditionally in EITHER direction (handle_propose), a
 * NEW_VIEW raised it on a `>` guard alone (handle_newview), and reaching
 * one's own view-change quorum set it (here). After this slice there is
 * exactly one writer in this file — bft_viewok_apply, below, on a proof
 * nodus_witness_bft_verify_view_proof accepted. The fifth writer,
 * nodus_witness_db.c's restore from disk, is UNTOUCHED and out of scope:
 * an attacker cannot write to another node's disk, so the restored value
 * is this node's own previously proven one. The cutover for the value
 * already on disk under the OLD rules is a deploy step, not code — see
 * nodus/docs/DEPLOY_RUNBOOK.md §2.1.
 *
 * WHY AN OUTCOME AND NOT A VOTE. A VIEW_OK statement says "I observed a
 * view-change quorum for this view, at this height, under this
 * committee". An honest node emits exactly one, at ONE instant — when
 * its own per-voter tally first reaches quorum. So a single honest
 * statement already testifies that 2f+1 committee members asked for the
 * view, and f+1 distinct statements contain at least one honest one.
 * Accumulating signed VOTES could never work: a voter re-emits at every
 * rung of the escalation ladder and nothing retracts.
 *
 * ⚠ THE EXACTLY-ONCE RULE IS WHAT THE f+1 ARGUMENT RESTS ON. It is
 * enforced by the accumulator itself: this node's own statement occupies
 * ONE slot keyed by its own voter id, and bft_viewok_emit_own returns
 * early when that slot is already filled for the anchor it is about to
 * speak on. The quorum check re-runs on every VIEW_CHANGE that arrives
 * after quorum, so without that latch one observation would become one
 * broadcast per late message.
 *
 * ⚠ PRE-GENESIS IS A HALT, AND IT IS DELIBERATE, NOT AN OVERSIGHT.
 * nodus_witness_bft_sign_view_ok refuses when the committee at the
 * height is EMPTY (its count-0 branch), and
 * nodus_witness_bft_verify_view_proof answers -2 there. On a chain with
 * no committee snapshot no statement can be signed, so no proof can
 * exist, so `current_view` can never move. A cluster whose GENESIS round
 * lands on a silent leader therefore cannot rotate away from it. This is
 * the direct consequence of making the counter proof-only while the
 * proof's authority is the committee, and it is stated here rather than
 * discovered later.
 * ════════════════════════════════════════════════════════════════════ */

/* The store mirrors nodus_t3_cert_entry_t so nodus_witness.h does not
 * have to depend on protocol/nodus_tier3.h, and the verifier takes the
 * wire type — so one is cast to the other. The C5 NEW_VIEW sender
 * already performs that cast on the same assumption and NOTHING was
 * checking it; these pin it at compile time. */
_Static_assert(sizeof(nodus_witness_prepared_sig_t) ==
                   sizeof(nodus_t3_cert_entry_t),
               "VIEW_OK store entry must be layout-identical to the wire "
               "cert entry it is cast to");
_Static_assert(offsetof(nodus_witness_prepared_sig_t, voter_id) ==
                   offsetof(nodus_t3_cert_entry_t, voter_id) &&
               sizeof(((nodus_witness_prepared_sig_t *)0)->voter_id) ==
                   sizeof(((nodus_t3_cert_entry_t *)0)->voter_id),
               "VIEW_OK store voter_id must match the wire voter_id");
_Static_assert(offsetof(nodus_witness_prepared_sig_t, signature) ==
                   offsetof(nodus_t3_cert_entry_t, signature) &&
               sizeof(((nodus_witness_prepared_sig_t *)0)->signature) ==
                   sizeof(((nodus_t3_cert_entry_t *)0)->signature),
               "VIEW_OK store signature must match the wire signature");
_Static_assert(DNAC_MAX_ACTIVE_VALIDATORS <= NODUS_T3_MAX_WITNESSES,
               "a full VIEW_OK statement set must fit the wire bundle");

/* Rate limits on the catch-up pair, in time_ms() milliseconds. Both are
 * LIVENESS-ONLY: they decide when a message is SENT, never whether a
 * received proof is believed, so no consensus decision rides on them.
 *
 * 1000 is the same interval the bootstrap w_chain_q limiter uses
 * (nodus_witness_bootstrap.c, NODUS_W_BOOTSTRAP_CHAIN_Q_MIN_INTERVAL_MS)
 * and time_ms() has ONE-SECOND granularity (time_ms above), so this is
 * "at most one per second boundary" — the finest limit expressible on
 * this clock. The response limit matters more than the request limit: an
 * answer carries f+1 signatures (~14 KB at n = 7, ~200 KB at n = 128) and
 * costs a Dilithium sign, so it is the amplification-worthy half. */
#define NODUS_W_VIEWOK_REQ_MIN_INTERVAL_MS  1000ULL
#define NODUS_W_VIEWOK_RSP_MIN_INTERVAL_MS  1000ULL

static void bft_viewok_set_anchor(nodus_witness_view_ok_set_t *s,
                                    uint64_t height, uint32_t view,
                                    const uint8_t set_hash[64]) {
    memset(s, 0, sizeof(*s));
    s->active = true;
    s->height = height;
    s->view   = view;
    memcpy(s->set_hash, set_hash, 64);
}

/* Slot holding `voter_id`, or -1 — bft_vc_find_voter's discipline
 * applied to the statement set. */
static int bft_viewok_find_voter(const nodus_witness_view_ok_set_t *s,
                                   const uint8_t *voter_id) {
    for (uint32_t i = 0; i < s->n_entries; i++) {
        if (memcmp(s->entries[i].voter_id, voter_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return (int)i;
    }
    return -1;
}

/* Record one statement. KEEP-FIRST, not upsert: a voter that already
 * holds a slot changes nothing.
 *
 * The preimage is fully determined by (height, view, set_hash,
 * voter_id), so a second statement from the same voter for the same
 * anchor can only be the same claim signed again — there is nothing for
 * it to say that the first did not. Overwriting would let a member
 * replace its own valid signature with garbage and pull the verified
 * count down by one; keeping the first denies it even that.
 *
 * @return true iff a NEW voter took a slot. */
static bool bft_viewok_set_put(nodus_witness_view_ok_set_t *s,
                                 const uint8_t *voter_id,
                                 const uint8_t *signature) {
    if (bft_viewok_find_voter(s, voter_id) >= 0) return false;
    if (s->n_entries >= DNAC_MAX_ACTIVE_VALIDATORS) return false;
    uint32_t slot = s->n_entries++;
    memcpy(s->entries[slot].voter_id, voter_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(s->entries[slot].signature, signature, NODUS_SIG_BYTES);
    return true;
}

/* The identified peer connection for `witness_id`, or NULL. */
static struct nodus_tcp_conn *bft_peer_conn(const nodus_witness_t *w,
                                              const uint8_t *witness_id) {
    for (int i = 0; i < w->peer_count; i++) {
        if (!w->peers[i].conn || !w->peers[i].identified) continue;
        if (memcmp(w->peers[i].witness_id, witness_id,
                   NODUS_T3_WITNESS_ID_LEN) == 0)
            return w->peers[i].conn;
    }
    return NULL;
}

/* Encode `msg` once and send it to ONE connection.
 *
 * nodus_witness_bft_broadcast's body minus the peer loop. NOT a refactor
 * of that function: broadcast carries a PROPOSE-only timestamp rule
 * (fill_header_with_ts, so a follower stores the leader's block
 * timestamp byte-identically), and no unicast verb carries a block
 * timestamp. Merging the two would put a PROPOSE-shaped branch on a path
 * that must never take it.
 *
 * HEAP, 1 MB, for the reason nodus_tier3.h states at nodus_t3_viewok_t:
 * an f+1 bundle is ~14 KB at n = 7 but ~200 KB at n = 128, and the
 * `uint8_t buf[NODUS_T3_MAX_MSG_SIZE]` pattern used by eleven send sites
 * in this tree is a 128 KB STACK buffer that breaks at n >= 42.
 * nodus_t3_verify allocates the same NODUS_W_MAX_SYNC_RSP_SIZE, so send
 * and verify stay symmetric.
 *
 * @return 0 if the frame reached the transport, -1 otherwise. */
static int bft_send_on_conn(nodus_witness_t *w, nodus_t3_msg_t *msg,
                              struct nodus_tcp_conn *conn) {
    if (!w || !msg || !conn || !w->server) return -1;

    fill_header(w, &msg->header);
    const char *method = nodus_t3_type_to_method(msg->type);
    if (method)
        snprintf(msg->method, sizeof(msg->method), "%s", method);

    uint8_t *buf = malloc(NODUS_W_MAX_SYNC_RSP_SIZE);
    if (!buf) {
        fprintf(stderr, "%s: malloc failed for T3 %s encode\n",
                LOG_TAG, msg->method);
        return -1;
    }
    size_t len = 0;
    if (nodus_t3_encode(msg, &w->server->identity.sk, buf,
                          NODUS_W_MAX_SYNC_RSP_SIZE, &len) != 0) {
        fprintf(stderr, "%s: failed to encode T3 %s\n", LOG_TAG, msg->method);
        free(buf);
        return -1;
    }
    int rc = nodus_tcp_send(conn, buf, len);
    free(buf);
    return (rc == 0) ? 0 : -1;
}

/* THE CATCH-UP ASK. Sent when this node refuses a consensus message
 * because the view it carries is not the view we hold, and only when the
 * SENDER is the one ahead.
 *
 * THE LIMIT IS KEYED ON THE BOUNDED ROSTER SLOT, never on the sender id
 * from the wire. A T3 sender identity costs one keypair plus one DHT put
 * (nodus/BUGS.md O15N-L4), so a free-form key would let an attacker mint
 * identities and grow the table without bound; the roster slot cannot
 * exceed NODUS_T3_MAX_WITNESSES by construction.
 *
 * The stamp is cleared for ALL peers when the view moves
 * (bft_viewok_apply), so "outstanding" self-releases on success, and it
 * re-arms after the interval so a lost or refused response cannot wedge
 * catch-up permanently. */
static void bft_viewok_send_request(nodus_witness_t *w,
                                      const uint8_t *peer_id) {
    if (!w || !peer_id) return;

    int slot = nodus_witness_roster_find(&w->roster, peer_id);
    if (slot < 0 || slot >= NODUS_T3_MAX_WITNESSES) return;

    uint64_t now  = time_ms();
    uint64_t last = w->viewok_req_sent_ms[slot];
    if (last != 0 && now < last + NODUS_W_VIEWOK_REQ_MIN_INTERVAL_MS)
        return;

    struct nodus_tcp_conn *conn = bft_peer_conn(w, peer_id);
    if (!conn) return;

    /* O15O Faz 1 — read the hint BEFORE building the message, so a fault
     * means NO REQUEST IS SENT rather than a request carrying height 1.
     * The hint authorises nothing, but it steers which view the peer
     * answers about, and asking about height 1 on a long chain wastes the
     * per-peer rate-limit slot on an answer we would then re-verify
     * against the wrong committee. Not sending costs one catch-up
     * attempt, which the interval re-arms. */
    uint64_t hint_tip = 0;
    if (nodus_witness_block_height_checked(w, &hint_tip) != 0) {
        fprintf(stderr, "%s: VIEW_OK — chain-height read faulted; not "
                "asking roster %d for its view proof (a hint of height 1 "
                "would be worse than no ask)\n", LOG_TAG, slot);
        return;
    }

    nodus_t3_msg_t q;
    memset(&q, 0, sizeof(q));
    q.type   = NODUS_T3_VIEWOK_REQ;
    q.txn_id = ++w->next_txn_id;
    /* A HINT, authorising nothing: the responder answers about the view
     * IT can prove, and we re-verify against the committee governing the
     * height carried inside its answer (nodus_tier3.h, w_viewok_q). */
    q.viewok_q.height_hint = hint_tip + 1;

    if (bft_send_on_conn(w, &q, conn) == 0) {
        w->viewok_req_sent_ms[slot] = now;
        fprintf(stderr, "%s: VIEW_OK — asked roster %d for the proof of the "
                "view it holds (we are at view %u, hint h=%llu)\n",
                LOG_TAG, slot, w->current_view,
                (unsigned long long)q.viewok_q.height_hint);
    }
}

/* Defined below, beside the rest of the VIEW_OK machinery. They are
 * declared here because bft_vc_check_quorum is what makes this node
 * SPEAK, and it sits above them so that the post-move block it used to
 * contain can stay in one piece directly underneath it. */
static int  bft_viewok_emit_own(nodus_witness_t *w, uint64_t height,
                                  uint32_t view);
static void bft_viewok_try_accumulator(nodus_witness_t *w);
/* Also needed above its definition: the PRE-GENESIS BOOTSTRAP path in
 * bft_vc_check_quorum moves the view itself and then owes the same
 * post-move work every other move owes. */
static void bft_view_move_finish(nodus_witness_t *w);

/* O15C-C D1 — view-change quorum check, factored out of handle_viewchg
 * so initiate_view_change can complete a quorum that its own self-record
 * finished. Returns 0 always (diagnostic parity with the old inline
 * tail).
 *
 * ⚠ O15N Faz 2C2 — THIS FUNCTION NO LONGER MOVES THE VIEW. Everything it
 * used to run after `w->current_view = w->view_change_target;` moved,
 * unchanged and in the same order, into bft_view_move_finish, which now
 * runs only at the proof site. Reaching quorum makes this node SPEAK —
 * it signs one VIEW_OK statement and broadcasts it — and nothing else.
 * Its own statement may be the f+1st if peers reached quorum first, so
 * the accumulator is tried immediately afterwards. */
static int bft_vc_check_quorum(nodus_witness_t *w) {
    /* O15H D9 — the quorum is counted AT THE TARGET, over per-voter
     * records. `view_change_count` is now the number of occupied slots
     * (voters with an opinion), which is >= the number backing THIS
     * target, so using it would complete a view change that no quorum
     * actually asked for. */
    if (!w->view_change_in_progress ||
        w->view_change_target <= w->current_view)
        return 0;

    /* ── O15O Faz 2 — WE DO NOT CERTIFY A QUORUM WE CANNOT COUNT ───────
     *
     * The tally test below is `< bft_config.quorum`, and
     * nodus_witness_bft_config_init writes quorum = 0 below
     * NODUS_T3_MIN_WITNESSES. At 0 the test is false for every tally, so
     * ANY tally at the target — one VIEW_CHANGE, our own self-record —
     * "reaches quorum".
     *
     * What that produces is not a local mistake but a signed artifact.
     * The next step is bft_viewok_emit_own, which signs a VIEW_OK
     * statement and broadcasts it, and a VIEW_OK means precisely "I
     * observed a quorum asking for this view". A node would put its
     * signature on that claim having observed one message — and peers
     * COUNT those statements toward the f+1 that moves their own view
     * (bft_viewok_apply). The same is true of the pre-genesis bootstrap
     * branch below, which moves this node's view on the strength of the
     * very tally being tested here.
     *
     * `return 0` matches this function's stated contract ("returns 0
     * always") and the fail-closed shape the height-fault arm below
     * already uses: the refusal is NOT EMITTING, never a changed return
     * code, because the callers at the handle_viewchg and
     * initiate_view_change tails propagate it as their own verdict.
     *
     * ⚠ THE TEXT BELOW DELIBERATELY AVOIDS "view change quorum! new
     * view:" — stagef test_vset_grow_shrink.sh section G counts that
     * exact string and an extra occurrence here would be a false
     * rotation in its ledger. */
    if (w->bft_config.quorum == 0) {
        fprintf(stderr, "%s: vacuous quorum — refusing to declare a "
                "view-change quorum for target %u on a quorum of 0 (%u "
                "voters at that target). A node with consensus disabled "
                "does not certify that anyone else reached one\n",
                LOG_TAG, w->view_change_target,
                bft_vc_tally(w, w->view_change_target));
        return 0;
    }

    if (bft_vc_tally(w, w->view_change_target) < w->bft_config.quorum)
        return 0;

    /* ⚠ LOAD-BEARING LOG LINE — DO NOT CHANGE ITS TEXT, DO NOT MOVE IT.
     *
     * `tests/integration/stagef/tests/test_vset_grow_shrink.sh` section G
     * COUNTS occurrences of this exact string before and after it kills
     * the epoch leader and requires an INCREASE. It pairs that count with
     * the persisted `pbft_state.current_view` advancing, and the harness
     * README states that BOTH are required because the count alone
     * cannot say where a rotation came from.
     *
     * WHAT IT MEANS CHANGED IN O15N Faz 2C2, WHAT IT SAYS DID NOT. It
     * used to sit immediately above the write that moved the view, so it
     * read as "the view moved". It now means "THIS NODE OBSERVED A
     * VIEW-CHANGE QUORUM" — which is exactly what section G needs from
     * it, because section G's other half (the persisted counter) is what
     * witnesses the actual move, and that move now happens at
     * bft_viewok_apply. Deleting this line, rewording it, or folding it
     * into the proof site would turn section G red on a healthy chain.
     * The wording "new view" is therefore kept deliberately, even though
     * the view is not new until the proof arrives. */
    fprintf(stderr, "%s: view change quorum! new view: %u\n",
            LOG_TAG, w->view_change_target);
    O15H_DIAG(w, "vc_quorum", w->my_id, w->round_state.block_height,
              w->current_view, w->view_change_target, w->round_state.phase,
              w->round_state.phase_start_time,
              time_ms() - w->round_state.phase_start_time, "-", 0,
              bft_vc_tally(w, w->view_change_target), w->bft_config.quorum,
              "view-change quorum reached");

    /* THE HEIGHT THE STATEMENT IS ABOUT is our next block height, NOT
     * `round_state.block_height`. Every committee gate in this file
     * resolves at `nodus_witness_block_height(w) + 1`, so signer and
     * reader measure against the same set; round_state's height is
     * written on round ENTRY only and an IDLE node's copy is the height
     * it LAST worked on, which two nodes at the same tip can disagree
     * about.
     *
     * ── O15O Faz 1 — THIS HEIGHT GOES INTO A SIGNED PREIMAGE.
     *
     * bft_viewok_emit_own signs a VIEW_OK statement over it and
     * broadcasts it. A fault answering 0 would put this node's signature
     * on a statement about height 1 — an artifact that outlives the fault
     * and that peers verify against the height-1 committee. So on a fault
     * we DO NOT EMIT. Read once, above both consumers: this is
     * single-threaded and nothing between them commits a block, so the
     * two reads the site used to make could only ever agree anyway.
     *
     * PLACED AFTER the load-bearing log line above, deliberately. That
     * line's text and position are pinned by stagef section G, and what
     * it asserts — that THIS NODE OBSERVED A VIEW-CHANGE QUORUM — is true
     * regardless of whether we can then read our height. Suppressing it
     * on a fault would turn section G red on a chain that is merely
     * degraded.
     *
     * RETURNS 0, not -1: this function's contract is "returns 0 always",
     * and callers at the handle_viewchg and initiate_view_change tails
     * propagate that value as the handler's verdict. The fail-closed
     * action here is NOT EMITTING, not a changed return code. */
    uint64_t vok_tip = 0;
    if (nodus_witness_block_height_checked(w, &vok_tip) != 0) {
        fprintf(stderr,
                "%s: VIEW_OK — chain-height read faulted; NOT signing a "
                "VIEW_OK statement. A statement about height 1 would be a "
                "signed artifact this node cannot take back\n", LOG_TAG);
        return 0;
    }
    int erc = bft_viewok_emit_own(w, vok_tip + 1,
                                  w->view_change_target);
    if (erc == 1) {
        /* ── PRE-GENESIS BOOTSTRAP PATH ───────────────────────────────
         *
         * No committee exists at this height, so no VIEW_OK statement
         * can be signed BY ANYONE — not by us and not by a peer. There
         * is therefore no proof to wait for, and waiting is not caution,
         * it is a permanent stop: a fresh cluster whose genesis round
         * lands on a silent leader could never rotate away from it and
         * the chain would never start.
         *
         * So in this window, and ONLY in this window, the node's own
         * observed quorum moves the view — which is exactly what this
         * function did before Faz 2C2. It is not a weaker rule than the
         * tree already applies here: pre-genesis the gossip roster IS
         * the documented authority, for leader election
         * (nodus_witness_bft_is_leader's count-0 branch) and for
         * prepared-certificate voter resolution (verify_prepared_cert's
         * count-0 branch) alike. The window closes the instant the
         * genesis block commits and seats a committee, after which
         * sign_view_ok stops returning 1 and the proof rule is the only
         * rule.
         *
         * The tally that got us here is the same one that got us here
         * before: `bft_vc_tally(target) >= bft_config.quorum`, over
         * per-voter records whose senders passed handle_viewchg's own
         * authorization. */
        uint32_t from = w->current_view;
        w->current_view = w->view_change_target;
        fprintf(stderr,
                "%s: VIEW_OK — PRE-GENESIS BOOTSTRAP: no committee at "
                "height %llu, so no statement can exist; moving view "
                "%u -> %u on our own observed quorum (%u/%u). This path "
                "is unavailable once genesis seats a committee.\n",
                /* O15O Faz 1 — the SAME height the statement was about,
                 * reused rather than re-queried. Reaching this branch
                 * means the checked read above succeeded, so there is no
                 * second fault to handle here; re-querying would only
                 * reintroduce one. */
                LOG_TAG, (unsigned long long)(vok_tip + 1),
                from, w->current_view,
                bft_vc_tally(w, w->view_change_target),
                w->bft_config.quorum);
        bft_view_move_finish(w);
        return 0;
    }
    bft_viewok_try_accumulator(w);
    return 0;
}

/* ── The post-move block ─────────────────────────────────────────────
 *
 * Everything a COMPLETED view change owes once the counter has actually
 * moved. Extracted verbatim from bft_vc_check_quorum's tail, in the same
 * order, so the measured defects its comments record (O15C-D.1's C5
 * self-bind and O15I P2's deadman arm) keep both their behaviour and
 * their reasoning.
 *
 * PRECONDITION, and the caller establishes it: `w->current_view` is the
 * view just entered and `w->view_change_target` equals it. The two
 * consumers below read the target rather than the view —
 * bft_self_record_view_change stamps our record at
 * `view_change_target`, and bind_reproposal_from_view_changes FILTERS
 * records on it (the O15H D9 filter that replaced the array wipe) — so
 * a proof that moved us to a view we were NOT chasing must re-point the
 * target first, or we would bind a certificate admitted for a view we
 * just left. When the proof carries us past our own target we then hold
 * no records at the new one and the binding CLEARS; that is
 * bind-or-clear working as designed, and safety at that height is held
 * by `last_prepared`, which is separate, persisted, and untouched
 * here. */
static void bft_view_move_finish(nodus_witness_t *w) {
    /* O15C-D.3 — our OWN evidence must be in our own decision, on THIS
     * path too. A node reaching quorum from peer VIEW_CHANGEs alone had
     * never run initiate_view_change, so its own prepared certificate was
     * absent from view_changes[] and the binding below was computed
     * without it. See bft_self_record_view_change for the measured
     * defect. This must run BEFORE the binding is computed. */
    bft_self_record_view_change(w);

    /* O15C-D.1 — C5 SELF-BIND.
     *
     * The C5 reproposal rule was armed ONLY in handle_newview, behind
     * `nv->new_view > w->current_view`. But every node advanced its own
     * view the moment it reached quorum, so by the time the leader's
     * NEW_VIEW arrived the guard was false and the whole accept block —
     * including the binding — was skipped, silently and with no log.
     * Proven on the live seven-node cluster (O15C-D.1): 7/7 nodes
     * self-advanced, ZERO logged "accepted NEW_VIEW", and the C5 gate in
     * handle_propose never evaluated once. The rule that is supposed to
     * stop a new leader substituting a different value for a prepared
     * one was therefore not being enforced on the common path.
     *
     * ⚠ O15N Faz 2C2 MADE THAT GUARD PERMANENTLY FALSE rather than
     * merely usually false: NEW_VIEW no longer writes the view at all,
     * so this self-bind is now the ONLY site that arms C5 on a view
     * change. The `==` adoption block in handle_newview can still
     * REPLACE the binding with a better verified certificate; it can no
     * longer be the thing that first sets it.
     *
     * A node entering a view holds the VIEW_CHANGE records for it, so it
     * can and must apply the same selection the leader applies.
     * BIND-OR-CLEAR: a stale binding from an earlier view would reject
     * every future proposal, so "no prepared cert" explicitly clears —
     * mirroring handle_newview's has_reproposal=false branch. */
    nodus_witness_bft_bind_reproposal_from_view_changes(w);
    /* H-5: persist the new view across restart. The ONE save that
     * follows the ONE write, and the caller must not repeat it.
     *
     * O15O Faz 3 — loud, and never a halt. The WAL / synchronous=NORMAL
     * durability boundary that makes the loss possible, and the owner's
     * decision to log rather than halt, are written out once in
     * nodus_witness_bft_after_successor_commit; this site only names the
     * fact IT loses. */
    if (nodus_witness_db_save_pbft_state(w) != 0) {
        fprintf(stderr,
            "%s: the NEW VIEW was NOT persisted (view=%u) — this node keeps "
            "consensus and stays in the view it just entered, but after a "
            "restart it may come back at a LOWER view than it reached\n",
            LOG_TAG, w->current_view);
    }
    w->view_change_in_progress = false;
    w->view_change_voted = false;
    w->round_state.phase = NODUS_W_PHASE_IDLE;

    /* ONE evaluation for the two decisions below. is_leader resolves the
     * committee from the DB and hashes its members, so asking twice
     * costs two lookups — and, more to the point, the arm decision and
     * the send decision must be the SAME answer by construction: every
     * node either waits or sends, never both and never neither. */
    bool i_am_leader = nodus_witness_bft_is_leader(w);

    /* ── O15I P2 — ARM THE PROPOSE-WAIT DEADMAN ────────────────────────
     *
     * The line above returned us to IDLE, and from IDLE
     * nodus_witness_bft_check_timeout returns at its first branch: no
     * timer is armed, so this node can never initiate a view change
     * again on its own. Only the leader leaves IDLE unprompted
     * (nodus_witness.c:1153-1162). A rotation onto a dead or silent
     * leader therefore left EVERY node sitting IDLE forever — the
     * 20-node terminal halt. This is the timer the two "our round then
     * times out and rotates the view" comments (:7049, :7623) already
     * assume exists.
     *
     * NOT THE LEADER. The new leader's job here is to SEND — it
     * broadcasts NEW_VIEW just below and may re-propose the retained
     * bytes. Arming it would make it time out against itself and rotate
     * away from a view it was about to serve.
     *
     * WHY THIS IS SAFE. Initiating a view change is always safe: it
     * asks, it does not decide. As of O15N Faz 2C2 `current_view` has
     * exactly TWO writers left in the whole tree — bft_viewok_apply in
     * this file, on a proof nodus_witness_bft_verify_view_proof
     * accepted, and nodus_witness_db.c's restore of this node's own
     * previously proven value. The three unproven message-driven writes
     * this comment used to enumerate (the PROPOSE copy, the quorum
     * self-advance, the NEW_VIEW `>` accept) are all gone. P2 adds
     * neither of the two that remain. No
     * vote content changes either: the fire site calls
     * nodus_witness_bft_initiate_view_change, which carries
     * `last_prepared` exactly as it does today.
     *
     * P2 ADDS NO C5 STATE. The next rotation recomputes the binding from
     * the prepared certs in view_changes[] through the existing
     * BIND-OR-CLEAR path (nodus_witness_bft_bind_reproposal_from_view_changes,
     * called above), so the C5 lock survives the rotation by the
     * mechanism that already owns it.
     *
     * LIVENESS, not churn: the deadline is armed ONLY in the aftermath
     * of a COMPLETED view change, so a quiet, healthy chain never arms
     * it at all — there is no idle-view churn on a cluster that is
     * simply out of transactions. */
    if (!i_am_leader) {
        w->awaiting_propose_deadline_ms =
            time_ms() + w->bft_config.round_timeout_ms;
    }

    /* F17 A4 — if we are the committee-derived new leader for the new
     * view, broadcast NEW_VIEW. is_leader already consults the chain
     * committee for the next block's target; the caller wrote
     * current_view before entering here, so the modulus picks up the new
     * view. */
    if (i_am_leader) {
        fprintf(stderr, "%s: we are new leader for view %u\n",
                LOG_TAG, w->current_view);

        nodus_t3_msg_t nv;
        memset(&nv, 0, sizeof(nv));
        nv.type = NODUS_T3_NEWVIEW;
        nv.txn_id = ++w->next_txn_id;
        nv.newview.new_view = w->current_view;
        /* O15H D9 — the voters backing THIS view, not the number of
         * occupied record slots. An observability field (tier3.h:297),
         * but one whose name promises the former; since records now
         * survive a target change the two numbers differ, and reporting
         * the slot count would overstate the support for this NEW_VIEW
         * to anyone reading a log or a capture. */
        nv.newview.n_proofs = bft_vc_tally(w, w->current_view);

        /* C5 — PBFT reproposal rule: pick the highest-height prepared
         * cert from the collected VIEW_CHANGE messages and bind the new
         * view's first PROPOSE to that tx_hash. If no view_change
         * carried a prepared cert, leave has_reproposal=false (leader
         * is free to propose anything). */
        /* Same selection every node just applied to bind itself, so the
         * broadcast binding and the local binding cannot diverge. */
        if (w->reproposal_required) {
            /* O15C-D.3 — ship the CERTIFICATE, not just the digest, so
             * every follower verifies the same decision. Locate the
             * record the binding came from and attach quorum-many
             * signatures sorted by voter_id (minimal sufficient proof,
             * one canonical encoding, and it keeps the message inside
             * NODUS_T3_MAX_MSG_SIZE). If we cannot produce a verifiable
             * cert we send NOTHING rather than a stripped claim — a
             * digest nobody can check is exactly the defect being
             * repaired, and rotation is the safe outcome. */
            int src = -1;
            for (int i = 0; i < w->view_change_count; i++) {
                const nodus_witness_vc_record_t *r = &w->view_changes[i];
                /* O15H D9 — same target filter as the binding scan; the
                 * certificate we SHIP must come from a record that
                 * actually backs the view we are opening. */
                if (r->target_view != w->current_view) continue;
                if (!r->prepared.has_prepared) continue;
                if (r->prepared.height != w->reproposal_height) continue;
                if (r->prepared.view != w->reproposal_prepared_view) continue;
                if (memcmp(r->prepared.tx_hash, w->reproposal_tx_hash,
                           NODUS_T3_TX_HASH_LEN) != 0) continue;
                src = i;
                break;
            }
            uint32_t take = 0;
            if (src >= 0 && w->view_changes[src].prepared.sigs) {
                uint32_t have = w->view_changes[src].prepared.n_sigs;
                take = (have > w->bft_config.quorum) ? w->bft_config.quorum
                                                     : have;
            }
            /* ── O15O Faz 2 — AT QUORUM 0 THE GUARD BELOW NEVER FIRES ──
             *
             * `take` is clamped to the quorum, so a quorum of 0 makes it
             * 0 too, and `0 < 0` is false: the check that exists to stop
             * us claiming a reproposal we cannot prove is bypassed by the
             * one value that means we cannot prove anything. This node
             * would broadcast a NEW_VIEW carrying has_reproposal = true,
             * a tx_hash, and reproposal_n_sigs = 0 — a binding every
             * follower is asked to honour with ZERO attached signatures.
             *
             * REACHABLE EVEN WITH THE SITE-5 GUARD IN PLACE. That guard
             * stops bft_vc_check_quorum from moving us here, but this
             * function's OTHER caller is bft_viewok_apply, on a VERIFIED
             * VIEW_OK proof — the recovery ladder, which is deliberately
             * not gated on the local config (it derives its own threshold
             * from the committee at the carried height). So a node with
             * quorum 0 can still be carried into a new view by a proof,
             * find itself leader, and reach this line.
             *
             * Same refusal as below, deliberately: bare `return`, no
             * NEW_VIEW, and the view rotates. */
            if (w->bft_config.quorum == 0) {
                fprintf(stderr, "%s: C5 vacuous quorum — refusing to claim a "
                        "reproposal on a quorum of 0 (height=%llu, %u sigs "
                        "available) — sending NO NEW_VIEW so the view "
                        "rotates\n", LOG_TAG,
                        (unsigned long long)w->reproposal_height,
                        (src >= 0 && w->view_changes[src].prepared.sigs)
                            ? w->view_changes[src].prepared.n_sigs : 0u);
                return;
            }

            if (take < w->bft_config.quorum) {
                fprintf(stderr, "%s: C5 cannot prove the reproposal "
                        "(height=%llu, sigs=%u < quorum=%u) — sending NO "
                        "NEW_VIEW so the view rotates\n", LOG_TAG,
                        (unsigned long long)w->reproposal_height, take,
                        w->bft_config.quorum);
                return;
            }

            nv.newview.has_reproposal = true;
            nv.newview.reproposal_height = w->reproposal_height;
            nv.newview.reproposal_prepared_view = w->reproposal_prepared_view;
            memcpy(nv.newview.reproposal_tx_hash, w->reproposal_tx_hash,
                   NODUS_T3_TX_HASH_LEN);

            /* Copy then insertion-sort by voter_id — canonical order. */
            for (uint32_t i = 0; i < take; i++)
                nv.newview.reproposal_sigs[i] =
                    *(const nodus_t3_cert_entry_t *)
                     (const void *)&w->view_changes[src].prepared.sigs[i];
            for (uint32_t i = 1; i < take; i++) {
                nodus_t3_cert_entry_t key = nv.newview.reproposal_sigs[i];
                int j = (int)i - 1;
                while (j >= 0 &&
                       memcmp(nv.newview.reproposal_sigs[j].voter_id,
                              key.voter_id, NODUS_T3_WITNESS_ID_LEN) > 0) {
                    nv.newview.reproposal_sigs[j + 1] =
                        nv.newview.reproposal_sigs[j];
                    j--;
                }
                nv.newview.reproposal_sigs[j + 1] = key;
            }
            nv.newview.reproposal_n_sigs = take;

            fprintf(stderr, "%s: C5 NEW_VIEW reproposal (height=%llu "
                    "prepared_view=%u, carrying %u sigs)\n", LOG_TAG,
                    (unsigned long long)w->reproposal_height,
                    w->reproposal_prepared_view, take);
        } else {
            fprintf(stderr, "%s: C5 NEW_VIEW with no reproposal "
                    "(free leader)\n", LOG_TAG);
        }

        nodus_witness_bft_broadcast(w, &nv);

        /* MED-28 — the binding we just broadcast is a DIGEST. Followers
         * will reject every PROPOSE at this height that does not match
         * it, and reproposal_required is only cleared by a matching one,
         * so a leader that does not actually re-propose wedges the
         * height permanently. If we retained the timed-out batch, re-
         * propose it now: start_round_from_entries recomputes the block
         * hash from the same tx_hashes in the same order, so the tx_root
         * equals the bound digest by construction.
         *
         * If we did NOT retain it (we never saw that PROPOSE), we stay
         * silent: our own round then times out and rotates the view to a
         * leader that did — standard PBFT liveness, no safety change. */
        if (nv.newview.has_reproposal) {
            (void)nodus_witness_try_repropose_retained(
                w, nv.newview.reproposal_height,
                nv.newview.reproposal_tx_hash);
        }
    }
}

/* Sign, record and broadcast THIS node's VIEW_OK statement for a view
 * change whose quorum we have just observed.
 *
 * @return 0 if a statement is present in the accumulator for this anchor
 *         (freshly emitted, or already there);
 *         1 PRE-GENESIS — no committee exists at this height, so no
 *         statement CAN be signed and the caller must take the bootstrap
 *         path (move on its own observed quorum);
 *         -1 if it could not be signed for any other reason. */
static int bft_viewok_emit_own(nodus_witness_t *w, uint64_t height,
                                 uint32_t view) {
    /* THE EXACTLY-ONCE LATCH. Our own slot in the accumulator IS the
     * latch: bft_vc_check_quorum re-runs on every VIEW_CHANGE that
     * arrives after quorum, and without this one observation would
     * become one broadcast per late message — and the f+1 rule would be
     * counting a node that spoke many times as many nodes if a peer ever
     * folded duplicates (it does not, but the invariant must hold at the
     * PRODUCER, which is where the argument is anchored). */
    if (w->viewok_acc.active && w->viewok_acc.height == height &&
        w->viewok_acc.view == view &&
        bft_viewok_find_voter(&w->viewok_acc, w->my_id) >= 0)
        return 0;

    uint8_t set_hash[64];
    nodus_sig_t sig;
    memset(&sig, 0, sizeof(sig));
    int src = nodus_witness_bft_sign_view_ok(w, height, view, set_hash, &sig);
    if (src == 1) {
        /* PRE-GENESIS. Not a fault and not a refusal — the committed
         * answer is that no committee exists at this height yet, so no
         * statement CAN be signed by anyone. Hand it up; the caller takes
         * the bootstrap path. See the count-0 branch of sign_view_ok for
         * why that is the tree's existing authority in this window and
         * not a new trust assumption. */
        return 1;
    }
    if (src != 0) {
        /* FAIL CLOSED, AND LEAVE EVERYTHING STANDING. This is now only
         * the committee-LOAD FAULT — a node that cannot read its own
         * committee. That is not a reason to abandon the view change:
         * view_change_in_progress, view_change_voted, the records and the
         * phase clock are all untouched, so the escalation ladder keeps
         * running and a later attempt succeeds once the committee is
         * readable again. We simply cannot certify what we observed, so
         * we say nothing. */
        fprintf(stderr, "%s: VIEW_OK — reached view-change quorum for view "
                "%u at height %llu but CANNOT SIGN the statement; the view "
                "does NOT move and the view change stands\n",
                LOG_TAG, view, (unsigned long long)height);
        return -1;
    }

    /* Re-anchor if this is a different (height, view, set_hash) than the
     * accumulator currently holds. Our own statement is authoritative
     * about what WE observed, so it wins over whatever was being
     * collected — a peer bundle cannot displace our own observation. */
    if (!w->viewok_acc.active || w->viewok_acc.height != height ||
        w->viewok_acc.view != view ||
        memcmp(w->viewok_acc.set_hash, set_hash, 64) != 0)
        bft_viewok_set_anchor(&w->viewok_acc, height, view, set_hash);

    (void)bft_viewok_set_put(&w->viewok_acc, w->my_id, sig.bytes);

    nodus_t3_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = NODUS_T3_VIEWOK;
    m.txn_id = ++w->next_txn_id;
    m.viewok.height = height;
    m.viewok.view = view;
    memcpy(m.viewok.set_hash, set_hash, 64);
    m.viewok.n_entries = 1;
    memcpy(m.viewok.entries[0].voter_id, w->my_id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m.viewok.entries[0].signature, sig.bytes, NODUS_SIG_BYTES);

    int sent = nodus_witness_bft_broadcast(w, &m);
    fprintf(stderr, "%s: VIEW_OK — statement emitted for view %u at height "
            "%llu (sent=%d); our own view stays %u until f+1 statements "
            "prove it\n", LOG_TAG, view, (unsigned long long)height, sent,
            w->current_view);
    return 0;
}

/* ⚠ THE ONE WRITER OF `w->current_view` IN THIS FILE.
 *
 * Verify one candidate proof and, if it holds for a view STRICTLY above
 * ours, move — then retain it and run the post-move block.
 *
 * @return  0 the view moved
 *         -1 a VERDICT: the proof does not hold
 *         -2 a node-local FAULT: this node cannot decide. Stay silent,
 *            do not blame the peer, do not drop the accumulator.
 *          1 the proof is INERT here: it is not about a higher view. */
static int bft_viewok_apply(nodus_witness_t *w, uint64_t height,
                              uint32_t view, const uint8_t set_hash[64],
                              const nodus_witness_prepared_sig_t *entries,
                              uint32_t n_entries) {
    if (!w || !entries || n_entries == 0) return -1;

    /* REPLAY / ALREADY THERE. A proof for a view at or below the one we
     * hold changes nothing — it is either the proof that moved us or an
     * older one, and re-applying either would only re-run the post-move
     * block against a view we already entered. */
    if (view <= w->current_view) return 1;

    int rc = nodus_witness_bft_verify_view_proof(
                 w, height, view, set_hash,
                 (const nodus_t3_cert_entry_t *)(const void *)entries,
                 n_entries);
    if (rc != 0) return rc;

    uint32_t from = w->current_view;

    /* ── THE WRITE ────────────────────────────────────────────────── */
    w->current_view = view;

    /* RETAIN, so this node can rescue the node behind it. Kept as it
     * ARRIVED, entry for entry: this is the evidence that convinced us,
     * and re-filtering it here would need a second membership resolution
     * whose answer could differ from the verifier's. A reader skips
     * whatever it does not recognise (verify_view_proof step 3), so
     * carrying a member's junk costs bytes and nothing else. */
    bft_viewok_set_anchor(&w->viewok_proof, height, view, set_hash);
    for (uint32_t i = 0; i < n_entries; i++)
        (void)bft_viewok_set_put(&w->viewok_proof, entries[i].voter_id,
                                 entries[i].signature);

    /* The ask self-releases on success: we have what we were asking for,
     * from whoever answered, so no peer is still owed a question. */
    memset(w->viewok_req_sent_ms, 0, sizeof(w->viewok_req_sent_ms));

    fprintf(stderr, "%s: VIEW_OK PROOF ACCEPTED — view %u -> %u at height "
            "%llu on %u statements\n", LOG_TAG, from, view,
            (unsigned long long)height, n_entries);
    O15H_DIAG(w, "viewok_move", w->my_id, w->round_state.block_height,
              w->current_view, w->view_change_target, w->round_state.phase,
              w->round_state.phase_start_time,
              time_ms() - w->round_state.phase_start_time, "VIEWOK", 0,
              n_entries, w->bft_config.quorum,
              "verified VIEW_OK proof moved the view");

    /* THE POST-MOVE PRECONDITION. bft_view_move_finish's two record
     * consumers read `view_change_target`, not `current_view`, so a
     * proof that carried us past the target we were chasing must
     * re-point it or the C5 selection would scan records admitted for a
     * view we just left. See that function's header. */
    w->view_change_target = w->current_view;
    bft_view_move_finish(w);
    return 0;
}

/* Try the ACCUMULATED statements as a proof.
 *
 * THE THRESHOLD USED HERE IS A CHEAP LOCAL PRE-GATE, NOT THE AUTHORITY.
 * bft_vc_join_threshold reads `w->bft_config.quorum` — the quorum in
 * force on THIS node — while nodus_witness_bft_verify_view_proof derives
 * the real f+1 from the committee governing the CARRIED height, which is
 * the only authority. The two agree whenever this node's config was
 * refreshed at the same height the statements are about, i.e. in every
 * ordinary case. When they disagree the cost is bounded and one-sided:
 * too high a pre-gate delays us until the `w_viewok_q` rescue delivers a
 * complete bundle (which bypasses this gate entirely), too low a
 * pre-gate spends verifies that verify_view_proof then declines. Neither
 * can make an unproven view move. */
static void bft_viewok_try_accumulator(nodus_witness_t *w) {
    const nodus_witness_view_ok_set_t *a = &w->viewok_acc;
    if (!a->active) return;
    if (a->view <= w->current_view) return;
    if (a->n_entries < bft_vc_join_threshold(w)) return;

    int rc = bft_viewok_apply(w, a->height, a->view, a->set_hash,
                                a->entries, a->n_entries);
    if (rc == -2) {
        /* THE FAULT ANSWER, AND THE ACCUMULATOR SURVIVES IT. -2 means
         * this node could not read its committee, has none at that
         * height, or resolved a DIFFERENT set than the one the signers
         * used. None of those is a statement about the evidence, so
         * discarding the evidence would be this node punishing peers for
         * its own blind spot — and it would have to be re-collected from
         * scratch once the blind spot cleared. */
        fprintf(stderr, "%s: VIEW_OK — cannot judge the %u accumulated "
                "statements for view %u at height %llu; keeping them\n",
                LOG_TAG, a->n_entries, a->view,
                (unsigned long long)a->height);
    }
}

/* Fold one bundle's statements into the accumulator.
 *
 * THE ANCHOR RULE, and its one deliberate asymmetry:
 *  - a STRICTLY HIGHER view RESETS the accumulator. Statements for
 *    different views are about different decisions and can never
 *    co-verify, so they must not share a count.
 *  - a LOWER view is IGNORED.
 *  - at the SAME view, a differing height or set hash is IGNORED. Both
 *    are inside the SIGNED preimage, so statements under a different
 *    anchor could not verify together no matter how many arrive; folding
 *    them would inflate the count with entries the verifier will drop.
 *
 * ⚠ THE RESET IS AN AMPLIFICATION SURFACE, stated rather than hidden. A
 * committee member can name an unreachably high view, reset this
 * accumulator, and its lone statement will never reach f+1 — so the
 * SINGLE-statement path can be starved by one message, repeatable. What
 * it CANNOT starve is the rescue: handle_viewok verifies a bundle that
 * already carries f+1 statements DIRECTLY, before and independently of
 * this fold, so the `w_viewok_q` answer still moves the view within one
 * round trip. The residual cost is therefore a delay, not a wedge.
 *
 * @return true iff at least one NEW voter took a slot. */
static bool bft_viewok_fold_bundle(nodus_witness_t *w,
                                     const nodus_t3_viewok_t *v,
                                     uint32_t n_entries) {
    nodus_witness_view_ok_set_t *a = &w->viewok_acc;

    if (!a->active || v->view > a->view) {
        bft_viewok_set_anchor(a, v->height, v->view, v->set_hash);
    } else if (v->view < a->view) {
        return false;
    } else if (v->height != a->height ||
               memcmp(v->set_hash, a->set_hash, 64) != 0) {
        return false;
    }

    bool changed = false;
    for (uint32_t i = 0; i < n_entries; i++) {
        if (bft_viewok_set_put(a, v->entries[i].voter_id,
                                 v->entries[i].signature))
            changed = true;
    }
    return changed;
}

int nodus_witness_bft_handle_viewok(nodus_witness_t *w,
                                      const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    /* C3 fix: refuse all BFT participation once safety_halt is latched. */
    if (w->safety_halt) return -1;

    const nodus_t3_viewok_t *v = &msg->viewok;
    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay CHECK — pure, records nothing. The matching nonce_record is
     * below the committee gate (O15O Faz 5). */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    if (v->n_entries == 0) return -1;
    uint32_t n_entries = v->n_entries;
    if (n_entries > NODUS_T3_MAX_WITNESSES)
        n_entries = NODUS_T3_MAX_WITNESSES;

    /* ── THE COMMITTEE GATE, BEFORE ANY SIGNATURE WORK ────────────────
     *
     * The SENDER must be a member of the committee governing the height
     * the bundle CARRIES — not of the transport roster, and not of the
     * committee at this node's own tip.
     *
     * WHY NOT THE ROSTER. A T3 sender identity costs one keypair plus
     * one DHT put (nodus/BUGS.md O15N-L4). Authorising on the roster
     * would let an attacker mint identities and make this node burn
     * Dilithium verifies (~370 µs each, perf harness) on the epoll
     * thread, one per entry per bundle. The committee is the bound that
     * turns that from unbounded into "at most the committee".
     *
     * WHY AT THE CARRIED HEIGHT. Same reason verify_view_proof resolves
     * there: authority comes from the evidence, not from where the
     * reader happens to stand. Using the local tip would make two nodes
     * at different heights reach different verdicts on identical bytes.
     *
     * A LOAD FAULT IS SILENCE. This node cannot name the authority, so
     * it has no verdict to give: no fold, no blame, no rotation. */
    int gossip_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (gossip_idx < 0) return -1;
    {
        nodus_committee_member_t *committee = NULL;
        int count = 0;
        int lc_rc = load_committee_at_height_alloc(w, v->height, &committee,
                                                     &count);
        if (lc_rc != 0) {
            free(committee);
            fprintf(stderr,
                    "%s: VIEW_OK — CANNOT ESTABLISH THE COMMITTEE at height "
                    "%llu (rc=%d%s); staying silent rather than judging the "
                    "sender on the transport roster\n",
                    LOG_TAG, (unsigned long long)v->height, lc_rc,
                    w->db ? "" : ", chain database not open");
            return -1;
        }
        if (count == 0) {
            /* The COMMITTED pre-genesis answer. There is no set to be a
             * member of, and no statement about that height could verify
             * anyway (verify_view_proof answers -2 there). Deliberately
             * NOT the gossip-roster bootstrap other gates take: this one
             * exists to bound signature work, and a roster fallback
             * would remove exactly the bound. */
            free(committee);
            fprintf(stderr,
                    "%s: VIEW_OK — no committee at height %llu; nothing to "
                    "measure membership against, dropping\n",
                    LOG_TAG, (unsigned long long)v->height);
            return -1;
        }
        int member = committee_find_pubkey(
            committee, count, w->roster.witnesses[gossip_idx].pubkey);
        free(committee);
        if (member < 0) {
            fprintf(stderr, "%s: VIEW_OK from non-committee sender "
                    "(roster %d, height %llu)\n", LOG_TAG, gossip_idx,
                    (unsigned long long)v->height);
            return -1;
        }
    }

    /* O15O Faz 5 — RECORD, below the committee gate and above the direct
     * verify and the accumulator fold. The gate above exists to BOUND the
     * signature work an unauthorised sender can make this node do; the
     * same reasoning applies to the cache capacity it can consume, so the
     * record belongs on the same side of it. */
    nonce_record(hdr->sender_id, hdr->nonce, hdr->timestamp);

    /* ── A BUNDLE THAT IS ALREADY A PROOF IS JUDGED ON ITS OWN ────────
     *
     * This is what makes the `w_viewok_q` rescue immune to an
     * accumulator a member has poisoned by naming an unreachable view
     * (see bft_viewok_fold_bundle). It is also why the n_entries >= 2
     * guard is here and not lower: 2 is the absolute floor
     * verify_view_proof enforces, and the ordinary broadcast carries
     * n_entries == 1 — so steady-state VIEW_OK traffic costs ZERO direct
     * verifies and only a claimed PROOF pays.
     *
     * ⚠ RESIDUAL, stated: a Byzantine COMMITTEE member can still send
     * unsolicited large bundles and make this node verify them. The
     * committee gate above is the bound on that, and it is the bound
     * this design chose. */
    if (n_entries >= 2 && v->view > w->current_view) {
        int rc = bft_viewok_apply(
            w, v->height, v->view, v->set_hash,
            (const nodus_witness_prepared_sig_t *)(const void *)v->entries,
            n_entries);
        if (rc == 0) return 0;
        /* -1 (does not hold on its own), -2 (we cannot judge) and 1
         * (inert) all fall through: a bundle short of f+1 is exactly
         * what the accumulator is for. */
    }

    if (!bft_viewok_fold_bundle(w, v, n_entries))
        return 0;               /* nothing new — no verify work to do */

    bft_viewok_try_accumulator(w);
    return 0;
}

int nodus_witness_bft_handle_viewok_req(nodus_witness_t *w,
                                          struct nodus_tcp_conn *conn,
                                          const nodus_t3_msg_t *msg) {
    if (!w || !msg || !conn) return -1;

    if (w->safety_halt) return -1;

    const nodus_t3_header_t *hdr = &msg->header;

    /* Replay CHECK — pure, records nothing. The matching nonce_record is
     * below the committee gate (O15O Faz 5). */
    if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
        return -1;
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    int gossip_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (gossip_idx < 0 || gossip_idx >= NODUS_T3_MAX_WITNESSES) return -1;

    /* NOTHING TO SAY IS A CORRECT ANSWER. A node at view 0 that never
     * moved holds no proof; so does a node whose last move predates a
     * restart, because the store is in-memory by design. Answering
     * nothing is right in both cases — the requester asks the next peer,
     * and its own escalation ladder keeps running meanwhile. */
    if (!w->viewok_proof.active || w->viewok_proof.n_entries == 0)
        return -1;

    /* The membership gate is the SAME shape as the one on the bundle
     * path, resolved at the height the ANSWER is about: only a member of
     * the committee that governs the proof may be handed the proof. The
     * request's height_hint is not consulted — it authorises nothing. */
    {
        nodus_committee_member_t *committee = NULL;
        int count = 0;
        int lc_rc = load_committee_at_height_alloc(
            w, w->viewok_proof.height, &committee, &count);
        if (lc_rc != 0 || count == 0) {
            free(committee);
            return -1;
        }
        int member = committee_find_pubkey(
            committee, count, w->roster.witnesses[gossip_idx].pubkey);
        free(committee);
        if (member < 0) {
            fprintf(stderr, "%s: w_viewok_q from non-committee sender "
                    "(roster %d)\n", LOG_TAG, gossip_idx);
            return -1;
        }
    }

    /* O15O Faz 5 — RECORD, below the committee gate and above the
     * per-roster-slot response limiter, which is this handler's only
     * state mutation (viewok_rsp_sent_ms).
     *
     * NOTE the "nothing to say" return above the gate: while this node
     * holds no proof it records nothing at all, so a requester whose ask
     * arrived too early is not refused as a replay when it asks again. */
    nonce_record(hdr->sender_id, hdr->nonce, hdr->timestamp);

    /* PER-ROSTER-SLOT RESPONSE LIMIT. An answer carries f+1 signatures
     * (~14 KB at n = 7, ~200 KB at n = 128) and costs a Dilithium sign,
     * so it is the amplification-worthy half of this pair — the same
     * shape as the bootstrap w_chain_q limiter
     * (nodus_witness_peer_t.last_chain_q_response_ms). Liveness-only: a
     * dropped answer is re-asked one second later. */
    uint64_t now  = time_ms();
    uint64_t last = w->viewok_rsp_sent_ms[gossip_idx];
    if (last != 0 && now < last + NODUS_W_VIEWOK_RSP_MIN_INTERVAL_MS)
        return -1;

    nodus_t3_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = NODUS_T3_VIEWOK;
    m.txn_id = ++w->next_txn_id;
    m.viewok.height = w->viewok_proof.height;
    m.viewok.view = w->viewok_proof.view;
    memcpy(m.viewok.set_hash, w->viewok_proof.set_hash, 64);
    uint32_t take = w->viewok_proof.n_entries;
    if (take > NODUS_T3_MAX_WITNESSES) take = NODUS_T3_MAX_WITNESSES;
    m.viewok.n_entries = take;
    for (uint32_t i = 0; i < take; i++) {
        memcpy(m.viewok.entries[i].voter_id,
               w->viewok_proof.entries[i].voter_id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(m.viewok.entries[i].signature,
               w->viewok_proof.entries[i].signature, NODUS_SIG_BYTES);
    }

    if (bft_send_on_conn(w, &m, conn) != 0) return -1;
    w->viewok_rsp_sent_ms[gossip_idx] = now;
    fprintf(stderr, "%s: VIEW_OK — answered roster %d with the retained "
            "proof of view %u at height %llu (%u statements)\n",
            LOG_TAG, gossip_idx, m.viewok.view,
            (unsigned long long)m.viewok.height, take);
    return 0;
}

int nodus_witness_bft_handle_newview(nodus_witness_t *w,
                                       const nodus_t3_msg_t *msg) {
    if (!w || !msg) return -1;

    /* C3 fix: refuse all BFT participation once safety_halt is latched. */
    if (w->safety_halt) return -1;

    const nodus_t3_newview_t *nv = &msg->newview;
    const nodus_t3_header_t *hdr = &msg->header;

    /* O15M — A REPLAY CHECK BELONGS HERE AND IS NOT SAFE TO ADD NAIVELY.
     * MEASURED, then REVERTED. Read this before trying again.
     *
     * THE GAP IS REAL, BUT O15N Faz 2C2 REMOVED WHAT MADE IT COST
     * ANYTHING. The other four consensus handlers call is_replay
     * (handle_propose, handle_vote, handle_commit, handle_viewchg). This
     * one still does not — and it USED to write `w->current_view` and
     * persist it, so a captured NEW_VIEW frame, validly signed forever,
     * could be re-sent at a chosen moment against a chosen subset to
     * move their view while others stayed put. That write is now gone:
     * this handler's remaining effects are the C5 adoption at `==` (a
     * cert it VERIFIES, and idempotent — re-adopting the same one
     * changes nothing) and the P2 disarm at `==` (which the paragraph at
     * that site argues is safe to replay precisely because it disarms
     * rather than re-arms). The masking write in handle_propose is gone
     * with it.
     *
     * WHY THE OBVIOUS FIX IS WRONG. Adding
     * `if (is_replay(hdr->sender_id, hdr->nonce, hdr->timestamp))
     *      return -1;` here — exactly the line the other four carry —
     * STALLS THE CHAIN. Measured 2026-08-28 on the 7-node harness at
     * DNAC_EPOCH_LENGTH=3 with precommit-drop injection
     * (NODUS_FAULT_DROP_TYPE=precommit, DROP_VC_ROTATE=2):
     * `test_newview_convergence.sh` fails with "chain did not advance
     * past 47 within 240 s". The SAME build with only this line removed
     * passes (rc=0). The phase-clock stamp added in the same season is
     * NOT implicated — that was the point of the bisect.
     *
     * The reasoning that justified adding it — "every send draws a fresh
     * CSPRNG nonce in fill_header (:761), so a genuine message can never
     * collide with the cache; only a byte-identical replay is refused" —
     * is TRUE about nonces and still did not predict the stall. Whatever
     * legitimately re-enters this handler is therefore NOT a fresh send:
     * candidates worth investigating before a second attempt are one
     * frame arriving over two connections to the same peer, and
     * is_replay INSERTING the nonce on a call whose handler later
     * refuses the message for a transient reason (committee not
     * loadable, cert unverifiable), so that the delivery which WOULD
     * have succeeded is then refused as a duplicate.
     *
     * ⚠ O15O Faz 5 CLOSED THE SECOND CANDIDATE, AND THAT CHANGES WHAT A
     * SECOND ATTEMPT WOULD COST — but it does NOT license re-adding the
     * line here. `is_replay` no longer inserts anything: recording is a
     * separate `nonce_record` call that each handler makes only after its
     * own committee gate. A transient committee-load failure therefore
     * burns no nonce anywhere in this file. The FIRST candidate — one
     * frame delivered twice — is untouched and would still be refused,
     * and the measured stall has never been attributed to either
     * candidate by evidence. The bar is unchanged: a second attempt needs
     * the mechanism identified and test_newview_convergence green.
     *
     * DO NOT re-add the bare line. A correct fix needs a replay rule
     * that admits the legitimate re-entry this scenario depends on, and
     * it needs test_newview_convergence green to prove it. */

    /* CRITICAL-2: Chain ID validation */
    if (!verify_chain_id(w, hdr->chain_id))
        return -1;

    /* F17 A3 — verify sender is the committee-derived expected leader
     * for the new view. F17 A5 bootstrap — fall back to gossip roster
     * when committee is empty (pre-genesis). */
    /* O15O Faz 1 — this height selects the committee that decides whether
     * the NEW_VIEW's sender is the expected leader for the new view, and
     * it is read TWICE more below to bound the reproposal height. A fault
     * answering 0 would rank the sender in the height-1 committee.
     * Refuse; same conclusion as the committee fault just below. Read
     * once and reuse: single-threaded, no commit in between. */
    uint64_t nv_tip = 0;
    if (nodus_witness_block_height_checked(w, &nv_tip) != 0) {
        fprintf(stderr, "%s: NEW_VIEW — chain-height read faulted; "
                "refusing rather than ranking the sender against the "
                "committee at height 1\n", LOG_TAG);
        return -1;
    }
    uint64_t next_bh = nv_tip + 1;
    nodus_committee_member_t *committee = NULL;
    int count = 0;
    int sender_idx = -1;

    int gossip_idx = nodus_witness_roster_find(&w->roster, hdr->sender_id);
    if (gossip_idx < 0) {
        fprintf(stderr, "%s: NEW_VIEW from unknown sender_id\n", LOG_TAG);
        return -1;
    }

    int lc_rc = load_committee_at_height_alloc(w, next_bh, &committee, &count);
    if (lc_rc != 0) {
        /* ── O15L Faz 4 / DG-4 / G4 — fail closed, mirroring the shipped
         * VOTE gate (O15J Block 2A). Ranking the sender in the transport
         * roster during a fault is how a non-member becomes "the expected
         * leader" and gets to install a new view.
         *
         * Cost is liveness only, and RT5 measured the shape: this
         * handler's return value is discarded by the dispatcher, so a
         * declining node produces no peer-blame and no rotation — it
         * stays in its old view, still holding its prepared-value lock. */
        free(committee);
        fprintf(stderr,
                "%s: NEW_VIEW — CANNOT ESTABLISH THE COMMITTEE at height "
                "%llu (rc=%d%s); refusing the new view rather than "
                "ranking its sender in the transport roster\n",
                LOG_TAG, (unsigned long long)next_bh, lc_rc,
                w->db ? "" : ", chain database not open");
        return -1;
    }
    if (count > 0) {
        sender_idx = committee_find_pubkey(committee, count,
                                             w->roster.witnesses[gossip_idx].pubkey);
    } else {
        /* rc == 0 && count == 0 — genuine pre-genesis bootstrap: leader is
         * a gossip-roster slot, by SORTED rank, exactly as
         * nodus_witness_bft_is_leader and the PROPOSE validator do. The
         * arrival index (gossip_idx) is node-local: two nodes holding the
         * same set but different arrival orders would disagree on who may
         * send NEW_VIEW, so a node could reject the honest new leader's
         * NEW_VIEW and the view change would never complete (O15C-D). */
        count = (int)w->roster.n_witnesses;
        sender_idx = nodus_witness_roster_sorted_find(&w->roster,
                                                        hdr->sender_id);
    }
    free(committee);
    committee = NULL;

    /* C7 fix: block-height epoch — cluster-agreed, no clock-skew fork risk */
    uint64_t epoch = next_bh / (uint64_t)DNAC_EPOCH_LENGTH;
    int expected_leader = nodus_witness_bft_leader_index(
        epoch, nv->new_view, count);
    if (sender_idx < 0 || sender_idx != expected_leader) {
        fprintf(stderr, "%s: NEW_VIEW from non-leader\n", LOG_TAG);
        return -1;
    }

    int sender_cm = sender_idx;  /* for downstream log */

    /* C5 — NEW_VIEW reproposal must match a prepared cert we saw in a
     * local VIEW_CHANGE for this new_view. This prevents a Byzantine
     * leader from binding the new view to a tx_hash nobody prepared.
     * has_reproposal=false means no VIEW_CHANGE in OUR log carried a
     * prepared cert — accept only if our local view_changes[] also has
     * no prepared entries (otherwise the leader is ignoring evidence
     * we hold). */
    /* ── O15C-D.3 — VERIFY THE CARRIED CERTIFICATE, do not consult our
     * own subset. REPLACES (not layers on) the previous local-subset
     * match, which asked "did I happen to receive a VIEW_CHANGE carrying
     * this cert?" — a question about message-delivery luck, not about
     * validity. view_changes[] is a node-local FIRST-2f+1 collection that
     * FREEZES at quorum, so two honest followers could permanently
     * disagree about the very same valid NEW_VIEW. The leader now ships
     * the certificate, so every validator verifies the SAME bytes. */
    if (nv->has_reproposal) {
        /* O15C-D.4 — SCHEMA BOUND TO VERSION, as its own named branch.
         *
         * Under protocol v3 the certificate fields are MANDATORY whenever
         * has_reproposal is set. A v2-shaped NEW_VIEW (digest only) would
         * otherwise die *incidentally* inside verify_prepared_cert, which
         * returns false on n_sigs == 0 — and a test aimed at incidental
         * behaviour proves nothing about the contract. This check exists
         * so "legacy schema under a v3 header" has a branch of its own,
         * and so the message is never reinterpreted with local fallback
         * semantics.
         *
         * Note this is reachable even with the dispatch version gate in
         * place: the gate rejects a v2 HEADER, while this rejects a v3
         * header carrying v2-shaped ARGS — the self-signed inconsistency
         * a peer could still construct, since it signs version and args
         * together. */
        if (nv->reproposal_n_sigs == 0) {
            fprintf(stderr, "%s: v%u NEW_VIEW claims a reproposal but "
                    "carries NO certificate (n_sigs=0) — legacy schema "
                    "under a current header; rejecting\n", LOG_TAG,
                    (unsigned)NODUS_T3_BFT_PROTOCOL_VER);
            return -1;
        }
        if (!nodus_witness_bft_verify_prepared_cert(
                w, nv->reproposal_height, nv->reproposal_prepared_view,
                nv->reproposal_tx_hash, nv->reproposal_sigs,
                nv->reproposal_n_sigs)) {
            fprintf(stderr, "%s: NEW_VIEW carried an UNVERIFIABLE prepared "
                    "cert (height=%llu prepared_view=%u n_sigs=%u) — "
                    "rejecting\n", LOG_TAG,
                    (unsigned long long)nv->reproposal_height,
                    nv->reproposal_prepared_view, nv->reproposal_n_sigs);
            return -1;
        }
        /* A leader may not bind a height the chain has already passed.
         *
         * O15O Faz 1 — reads the tip CHECKED at the top of this handler
         * (nv_tip) instead of re-querying. A fault answering 0 would let
         * a leader bind ANY height above 0, i.e. re-bind a height this
         * chain has long committed; the handler already returned -1 on
         * that fault before reaching here. Nothing between the read and
         * this line commits a block, so the value is the same one the
         * re-query would have produced. */
        if (nv->reproposal_height <= nv_tip) {
            fprintf(stderr, "%s: NEW_VIEW reproposal height %llu is at or "
                    "below the committed head — rejecting\n", LOG_TAG,
                    (unsigned long long)nv->reproposal_height);
            return -1;
        }
    } else {
        /* Leader claims no reproposal. Our OWN uncommitted prepared value
         * is authoritative evidence it must not ignore — and unlike
         * view_changes[], it cannot go missing through delivery accident.
         * (Checking the frozen subset here was the D.3 gap: a carrier
         * with no self-record would have accepted a leader discarding
         * its own evidence.) */
        /* O15O Faz 1 — same checked tip (nv_tip) as the branch above. A
         * fault answering 0 would make every held prepared value look
         * uncommitted and reject every NEW_VIEW that honestly carries no
         * reproposal; the handler already returned -1 on that fault. */
        if (w->last_prepared.present &&
            w->last_prepared.height > nv_tip) {
            fprintf(stderr, "%s: NEW_VIEW has_reproposal=false but WE hold "
                    "an uncommitted prepared value at height %llu — "
                    "rejecting\n", LOG_TAG,
                    (unsigned long long)w->last_prepared.height);
            return -1;
        }
    }

    /* ── O15C-D.3 — ADOPTION AT new_view == current_view ─────────────
     *
     * A node that reached the new view on its own evidence has
     * current_view already equal to nv->new_view, so a `>` guard makes
     * an accept block a silent no-op — which is precisely how a follower
     * ended up enforcing a binding derived from its own frozen subset
     * while the leader proposed a different, equally valid one. The
     * certificate is now VERIFIED (above), so we can converge on it
     * rather than on an accident of delivery.
     *
     * ⚠ O15N Faz 2C2 — `==` IS NOW THE ONLY CASE THAT DOES ANYTHING.
     * NEW_VIEW no longer writes the view (see the refusal at the bottom
     * of this function), so this block is where the whole C5 adoption
     * rule lives. It can still REPLACE a binding with a better verified
     * certificate; the first binding is now always set by
     * bft_view_move_finish at the proof site.
     *
     * Adopt iff the verified cert OUTRANKS our own binding under the D.2
     * canonical order (height, view, tx_hash). If ours strictly outranks
     * the carried one we keep ours and do NOT reject the view: safety is
     * held by the prepared-value lock either way, and rotation resolves
     * the rest. Idempotent — re-adopting the same cert changes nothing,
     * so a replayed NEW_VIEW is inert. */
    if (nv->new_view == w->current_view && nv->has_reproposal) {
        bool adopt = !w->reproposal_required;
        if (!adopt) {
            if (nv->reproposal_height != w->reproposal_height)
                adopt = nv->reproposal_height > w->reproposal_height;
            else if (nv->reproposal_prepared_view != w->reproposal_prepared_view)
                adopt = nv->reproposal_prepared_view >
                        w->reproposal_prepared_view;
            else
                adopt = memcmp(nv->reproposal_tx_hash, w->reproposal_tx_hash,
                               NODUS_T3_TX_HASH_LEN) > 0;
        }
        if (adopt) {
            w->reproposal_required = true;
            w->reproposal_height = nv->reproposal_height;
            w->reproposal_prepared_view = nv->reproposal_prepared_view;
            memcpy(w->reproposal_tx_hash, nv->reproposal_tx_hash,
                   NODUS_T3_TX_HASH_LEN);
            fprintf(stderr, "%s: C5 ADOPTED the NEW_VIEW's verified cert "
                    "(height=%llu prepared_view=%u) at view %u\n", LOG_TAG,
                    (unsigned long long)nv->reproposal_height,
                    nv->reproposal_prepared_view, w->current_view);
        } else {
            fprintf(stderr, "%s: C5 kept our own binding — it outranks the "
                    "NEW_VIEW's cert (ours h=%llu v=%u)\n", LOG_TAG,
                    (unsigned long long)w->reproposal_height,
                    w->reproposal_prepared_view);
        }
    }

    /* ── O15I P2 — THE DEADMAN RULE ON THE *COMMON* PATH ───────────────
     *
     * O15C-D.1 measured that a `>`-guarded accept block is a silent
     * no-op on the ordinary path: every node reaches the new view on its
     * own evidence before the leader's NEW_VIEW arrives, so new_view ==
     * current_view (7/7 nodes advanced, ZERO logged "accepted
     * NEW_VIEW"). Putting the P2 disarm ONLY in such a block would
     * therefore mean it never runs where it matters: a follower armed by
     * bft_view_move_finish would receive the live leader's
     * has_reproposal=false NEW_VIEW, never disarm, and on a quiet chain
     * (empty mempool → no PROPOSE is due) fire after one window →
     * rotate → arm again → idle view churn on a cluster whose leader is
     * perfectly healthy. So the rule is applied HERE, at `==`.
     *
     * has_reproposal == FALSE → DISARM. The leader has proven liveness
     * by producing a NEW_VIEW, and it owes no bound PROPOSE. A stall
     * with nothing pending is a demand-driven stall, which is a
     * different mechanism's problem, not this deadman's.
     *
     * has_reproposal == TRUE → DELIBERATELY UNTOUCHED. We armed with a
     * full window against exactly this leader, and the MANDATORY
     * re-proposal is what that window is for. Re-arming here would be
     * worse than a no-op: this handler has no replay guard, so a peer
     * replaying one NEW_VIEW frame per window could postpone the deadman
     * indefinitely — a liveness attack costing one stored message.
     *
     * ⚠ O15N Faz 2C2 — THE `>` HALF OF THIS RULE IS GONE WITH ITS BLOCK,
     * AND ITS RE-ARM IS NOT CARRIED OVER HERE. That re-arm was correct
     * only because `>` was a genuine view ADVANCE and the transition
     * that first set the binding; at `==` neither is true, and adding it
     * would hand a replayer the postponement the paragraph above
     * refuses. The same reasoning deletes rather than moves the `>`
     * block's other side effects: its `view_change_in_progress = false`
     * would silently abandon a view change we are running for a HIGHER
     * target, and its round_state reset to IDLE would let a replayed
     * NEW_VIEW kill a live round.
     *
     * Placed after every validation above has passed, so an unverifiable
     * or non-leader NEW_VIEW can never move our timer. */
    if (nv->new_view == w->current_view && !nv->has_reproposal) {
        if (w->awaiting_propose_deadline_ms != 0) {
            fprintf(stderr, "%s: P2 disarmed — NEW_VIEW at our own view %u "
                    "proves the leader is live and binds no reproposal\n",
                    LOG_TAG, w->current_view);
        }
        w->awaiting_propose_deadline_ms = 0;
    }

    /* ── O15N Faz 2C2 — A NEW_VIEW DOES NOT MOVE THE COUNTER ──────────
     *
     * WHAT WAS HERE. `if (nv->new_view > w->current_view) {
     * w->current_view = nv->new_view; ... }` — a view ADVANCE on a `>`
     * guard and one signature. That is one node deciding this node's
     * leader election. This handler also has no replay guard and cannot
     * safely be given one (see the measured O15M note at the top of this
     * function), so a captured NEW_VIEW frame stays validly signed
     * forever and could be re-sent at a chosen moment against a chosen
     * subset. Until now the damage was masked by handle_propose copying
     * the view back DOWN unconditionally — a second unproven write
     * covering for the first.
     *
     * WHAT NEW_VIEW STILL DOES, unchanged: it carries the C5 reproposal
     * certificate, and the adoption block above applies it at `==`. That
     * was always its safety-relevant job; moving the counter was not.
     *
     * A HIGHER new_view now means WE ARE BEHIND, so we ask its sender
     * for the proof. The sender passed the committee + expected-leader
     * checks above before we get here (O15N round 1, K-6: asking before
     * those checks would let any roster member drive a victim into
     * asking instead of participating). A LOWER new_view means the
     * SENDER is behind; it can teach us nothing and it will ask us when
     * it refuses our traffic. */
    if (nv->new_view > w->current_view) {
        fprintf(stderr, "%s: NEW_VIEW %u from leader %d is above our view "
                "%u — the counter moves only on a verified VIEW_OK proof; "
                "asking for it\n", LOG_TAG, nv->new_view, sender_cm,
                w->current_view);
        bft_viewok_send_request(w, hdr->sender_id);
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════════
 * Timeout check (called from nodus_witness_tick)
 * ════════════════════════════════════════════════════════════════════ */

/* O15C-D.3 — verify a prepared certificate presented on the wire.
 *
 * Counts how many of the supplied (voter_id, signature) pairs verify
 * against the 116-byte purpose-0x07 PREPARED preimage built from
 * (chain_id, view, height, tx_hash) — chain_id read from `w`, so a
 * certificate is bound to THIS chain and a pre-wipe one cannot be
 * replayed onto its successor — resolving each voter's public key through
 * the committee governing `height`, falling back to the gossip roster on
 * pre-genesis chains — the SAME resolution and the SAME preimage
 * handle_viewchg already applies to a VIEW_CHANGE's cert. A duplicate
 * voter is counted once, so a leader cannot manufacture quorum by
 * repeating one signature.
 *
 * @return true iff at least `w->bft_config.quorum` DISTINCT voters
 *         verify. Anything short of that — malformed, insufficient,
 *         unknown voters, wrong preimage — is false, i.e. fail-closed.
 *
 * Used by handle_newview to check the certificate the leader now carries
 * (O15C-D.3 wire), so every validator verifies the SAME decision instead
 * of consulting its own frozen first-2f+1 subset. */
bool nodus_witness_bft_verify_prepared_cert(nodus_witness_t *w,
                                              uint64_t height,
                                              uint32_t view,
                                              const uint8_t *tx_hash,
                                              const nodus_t3_cert_entry_t *sigs,
                                              uint32_t n_sigs) {
    if (!w || !tx_hash || !sigs || n_sigs == 0) return false;
    if (n_sigs > NODUS_T3_MAX_WITNESSES) return false;

    uint8_t prep_preimage[NODUS_WITNESS_PREPARED_PREIMAGE_LEN];
    if (compute_prepared_preimage(view, height, tx_hash, w->chain_id,
                                    prep_preimage) != 0)
        return false;

    nodus_committee_member_t *committee = NULL;
    int c_count = 0;
    int lc_rc = load_committee_at_height_alloc(w, height, &committee, &c_count);
    if (lc_rc != 0) {
        /* ── O15L Faz 4 / DG-4 / G4 — THE HIGHEST-VALUE OF THE FIVE
         * (red-team F-1). A fault used to leave have_committee false, and
         * the voter-key resolution below then fell through to the GOSSIP
         * ROSTER while the threshold came from w->bft_config.quorum:
         * membership from one authority, threshold from another — the
         * two-authority split this function's own O15H C5 comment names
         * as the fork shape.
         *
         * The roster is admitted from self-signed DHT nodus:pk
         * registrations with NO committee check
         * (nodus_witness_peer.c), so an attacker seating quorum-many keys
         * there could forge a prepared certificate binding a faulting
         * victim to a value nobody prepared, at a height of its choosing.
         *
         * There is no safe answer to give here without the committee, so
         * give none: a certificate that cannot be checked is not a
         * certificate. Fail closed, exactly as the function's own
         * contract already promises for every other unverifiable input
         * ("Anything short of that ... is false, i.e. fail-closed"). */
        free(committee);
        fprintf(stderr,
                "%s: C5 prepared cert — CANNOT ESTABLISH THE COMMITTEE at "
                "height %llu (view=%u rc=%d%s); refusing the certificate "
                "rather than resolving its voters from the transport "
                "roster\n",
                LOG_TAG, (unsigned long long)height, view, lc_rc,
                w->db ? "" : ", chain database not open");
        return false;
    }
    /* rc == 0 && c_count == 0 is a committed answer — a chain with no
     * committee at this height (pre-genesis), where the roster IS the
     * documented bootstrap authority. Preserved verbatim. */
    bool have_committee = (c_count > 0);

    uint32_t verified = 0;
    for (uint32_t i = 0; i < n_sigs; i++) {
        const uint8_t *vid = sigs[i].voter_id;

        /* Duplicate voters must not inflate the count — otherwise one
         * valid signature repeated quorum-many times would "prove" a
         * certificate nobody else signed. */
        bool dup = false;
        for (uint32_t j = 0; j < i; j++) {
            if (memcmp(sigs[j].voter_id, vid, NODUS_T3_WITNESS_ID_LEN) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        const uint8_t *voter_pk = NULL;
        if (have_committee) {
            for (int ci = 0; ci < c_count; ci++) {
                nodus_key_t fp;
                if (qgp_sha3_512(committee[ci].pubkey, DNAC_PUBKEY_SIZE,
                                  fp.bytes) == 0 &&
                    memcmp(fp.bytes, vid, NODUS_T3_WITNESS_ID_LEN) == 0) {
                    voter_pk = committee[ci].pubkey;
                    break;
                }
            }
        }
        /* O15H C5 — MEMBERSHIP AUTHORITY IS THE COMMITTEE AT `height`,
         * FULL STOP.
         *
         * The gossip roster fallback used to run whenever a signer was
         * not found in that committee, which quietly readmitted exactly
         * the signers the committee had excluded — the transport roster
         * deciding consensus membership, the same defect class O15G
         * removed from cert verification. The fallback survives ONLY for
         * a chain that HAS no committee at that height (pre-genesis),
         * where the roster is the documented bootstrap authority. */
        if (!voter_pk && !have_committee) {
            int ri = nodus_witness_roster_find(&w->roster, vid);
            if (ri >= 0) voter_pk = w->roster.witnesses[ri].pubkey;
        }
        if (!voter_pk) continue;

        nodus_sig_t sig_in;
        nodus_pubkey_t pk_in;
        memcpy(sig_in.bytes, sigs[i].signature, NODUS_SIG_BYTES);
        memcpy(pk_in.bytes, voter_pk, NODUS_PK_BYTES);
        if (nodus_verify_prepared_vote(&sig_in, prep_preimage,
                                        sizeof(prep_preimage), &pk_in) == 0)
            verified++;
    }

    /* O15H C5 — THE THRESHOLD IS THE QUORUM OF THAT SAME COMMITTEE.
     *
     * It used to be w->bft_config.quorum — the quorum in force NOW —
     * while the signers were resolved from the committee governing
     * `height`. Two authorities for one decision, and they disagree
     * across every committee change:
     *
     *   set GREW  — a value genuinely prepared under the old, smaller
     *               quorum is judged against the new, larger one and
     *               DISCARDED. C5 exists to stop a new leader
     *               substituting a different value for one that may
     *               already have been committed; discarding the cert is
     *               how that becomes a FORK.
     *   set SHRANK — a cert below the old quorum passes the new, smaller
     *               one and binds the view to a value nobody prepared.
     *
     * A value could have been committed at `height` iff someone
     * assembled a PREPARE quorum under the committee governing
     * `height`. So that committee's size decides the threshold, and
     * dna_bft_quorum is the same function every other quorum on this
     * chain is derived from. Reachable whenever a height stays pending
     * across an epoch boundary — the growth boundary this season is
     * about. */
    uint32_t required = have_committee
                          ? dna_bft_quorum((uint32_t)c_count)
                          : w->bft_config.quorum;

    /* ── O15O Faz 2 — THE PRE-GENESIS ARM MUST NOT ANSWER 0 ────────────
     *
     * The `have_committee == false` arm above is the documented F17 A5
     * pre-genesis authority and STAYS. What cannot stay is the value it
     * can carry: nodus_witness_bft_config_init writes quorum = 0 for a
     * roster below NODUS_T3_MIN_WITNESSES, and `verified >= 0` is true
     * for every input — including `verified == 0`, i.e. a certificate in
     * which not one signature checked out. This function's own contract
     * promises the opposite ("Anything short of that ... is false, i.e.
     * fail-closed"), and its own comment eight lines up records why the
     * roster is the wrong thing to trust unaided: entries are admitted
     * from self-signed DHT nodus:pk registrations with no committee check
     * (nodus_witness_peer.c).
     *
     * SO IT REFUSES, IT DOES NOT FLOOR. A floor of 2 — the shape
     * bft_vc_join_threshold uses — is right for THAT function, which is
     * deciding when this node may SPEAK, and where the floor is an
     * anti-amplification backstop. Here the question is whether a
     * CERTIFICATE carries authority, and lowering the bar to 2 would turn
     * "an attacker needs quorum-many self-registered keys" into "an
     * attacker needs two". Fail-closed is `false`.
     *
     * NOTHING LEGITIMATE LOSES BY IT. A fresh cluster only reaches the
     * genesis round at all by passing the C-1 seed gate
     * (nodus_witness_bootstrap.c, seed_count >= DNAC_COMMITTEE_SIZE), so
     * a real pre-genesis node's roster is at or above the committee size
     * and its quorum is well clear of 0. And the caller's response to
     * `false` is to drop the reproposal and rotate the view, which is the
     * safe outcome the C5 path is built around. */
    if (required == 0) {
        free(committee);
        fprintf(stderr,
                "%s: C5 vacuous quorum — refusing the certificate at height "
                "%llu (view=%u, %u/%u signatures verified) rather than "
                "accepting it against a threshold of 0. The pre-genesis "
                "roster fallback has no quorum to offer: consensus is "
                "disabled on this node\n",
                LOG_TAG, (unsigned long long)height, view, verified, n_sigs);
        return false;
    }

    bool ok = (verified >= required);
    if (!ok) {
        fprintf(stderr, "%s: C5 prepared cert REJECTED (height=%llu view=%u "
                "verified=%u/%u required=%u committee=%d)\n", LOG_TAG,
                (unsigned long long)height, view, verified, n_sigs,
                required, have_committee ? c_count : -1);
    }

    free(committee);
    return ok;
}

/* ════════════════════════════════════════════════════════════════════
 * O15N Faz 2B — VIEW_OK: producing and verifying view AUTHORITY
 *
 * PURE PRIMITIVES. Neither function reads or writes w->current_view,
 * w->view_change_* or any round state; both take everything they judge
 * as an argument, and both are decided by the committee governing the
 * height they are given.
 *
 * ⚠ THEY ARE NO LONGER INERT. Faz 2C2 WIRED THEM: sign_view_ok is called
 * from bft_vc_check_quorum when this node's own tally reaches quorum,
 * and verify_view_proof is called from bft_viewok_apply, which is the
 * ONE site in this file that assigns to w->current_view. Read the Faz
 * 2C2 banner above bft_vc_check_quorum before changing either
 * function's semantics — the f+1 rule below now decides when a live
 * cluster rotates its leader.
 * ════════════════════════════════════════════════════════════════════ */

int nodus_witness_bft_sign_view_ok(nodus_witness_t *w,
                                     uint64_t height, uint32_t view,
                                     uint8_t set_hash_out[64],
                                     nodus_sig_t *sig_out) {
    if (!w || !set_hash_out || !sig_out) return -1;
    if (!w->server) return -1;

    /* The committee at the height the statement is ABOUT — the same
     * authority a reader will resolve, so signer and verifier measure
     * against one set. */
    nodus_committee_member_t *committee = NULL;
    int c_count = 0;
    int lc_rc = load_committee_at_height_alloc(w, height, &committee, &c_count);
    if (lc_rc != 0) {
        /* A node that cannot establish who is entitled to decide must not
         * certify a decision. Same fail-closed rule as is_leader and
         * verify_prepared_cert above. */
        free(committee);
        fprintf(stderr,
                "%s: VIEW_OK — CANNOT ESTABLISH THE COMMITTEE at height "
                "%llu (view=%u rc=%d%s); refusing to sign a statement whose "
                "authority this node cannot name\n",
                LOG_TAG, (unsigned long long)height, view, lc_rc,
                w->db ? "" : ", chain database not open");
        return -1;
    }
    if (c_count == 0) {
        /* rc 0 with count 0 is a COMMITTED answer — pre-genesis, no
         * committee at this height. A set hash over an EMPTY set is not a
         * statement about anything, so this still refuses to SIGN, and
         * compute_committee_set_hash never has to invent a value for
         * count 0.
         *
         * ⚠ BUT IT IS ITS OWN ANSWER, NOT A FAULT — RETURN 1, NOT -1.
         *
         * O15N Faz 2C2 made the verified proof the ONLY writer of
         * current_view. Combined with a bare -1 here that LOCKED a
         * pre-genesis chain: no committee exists until the genesis block
         * commits, so no node could sign, so no proof could exist, so the
         * view could never move — and a fresh cluster whose genesis round
         * landed on a silent leader could never rotate away from it. The
         * chain would simply never start. Two shipped unit tests said so
         * out loud (test_bft_liveness, test_witness_newview_convergence),
         * and the Genesis Protocol harness builds exactly that state on
         * every run.
         *
         * The caller answers 1 by taking the PRE-GENESIS BOOTSTRAP path:
         * it moves the view on its own observed quorum, which is what
         * this code did before Faz 2C2. That is not a new trust
         * assumption — pre-genesis the gossip roster IS the documented
         * authority in this tree, for leader election
         * (nodus_witness_bft_is_leader) and for prepared-certificate
         * voter resolution (verify_prepared_cert) alike. This applies it
         * to the third path in the same window, and the window closes the
         * instant the genesis block commits and seats a committee. */
        free(committee);
        fprintf(stderr,
                "%s: VIEW_OK — no committee at height %llu (view=%u, "
                "pre-genesis); cannot sign a set hash over an empty set, "
                "falling back to the documented bootstrap authority\n",
                LOG_TAG, (unsigned long long)height, view);
        return 1;
    }

    uint8_t set_hash[64];
    if (compute_committee_set_hash(committee, c_count, set_hash) != 0) {
        free(committee);
        fprintf(stderr,
                "%s: VIEW_OK — committee set-hash over %d members failed at "
                "height %llu; refusing to sign\n",
                LOG_TAG, c_count, (unsigned long long)height);
        return -1;
    }
    free(committee);
    committee = NULL;

    uint8_t preimage[NODUS_WITNESS_VIEWOK_PREIMAGE_LEN];
    if (compute_view_ok_preimage(height, view, set_hash, w->my_id,
                                   w->chain_id, preimage) != 0) {
        return -1;
    }

    if (nodus_sign_view_ok(sig_out, preimage, sizeof(preimage),
                             &w->server->identity.sk) != 0) {
        fprintf(stderr, "%s: VIEW_OK — signing failed at height %llu view "
                "%u\n", LOG_TAG, (unsigned long long)height, view);
        return -1;
    }

    /* Returned so the caller can carry the set hash it was signed under —
     * a reader that resolves a different set must be able to SEE that,
     * not silently judge with the wrong denominator. */
    memcpy(set_hash_out, set_hash, 64);
    return 0;
}

int nodus_witness_bft_verify_view_proof(nodus_witness_t *w,
                                          uint64_t height, uint32_t view,
                                          const uint8_t set_hash[64],
                                          const nodus_t3_cert_entry_t *entries,
                                          uint32_t n_entries) {
    if (!w || !set_hash || !entries || n_entries == 0) return -1;
    if (n_entries > NODUS_T3_MAX_WITNESSES) return -1;

    /* ── STEP 1 — the committee at the CARRIED height ─────────────────
     * Never at this node's own tip. The whole point of a proof is that
     * its authority comes from the EVIDENCE, not from where the reader
     * happens to be; resolving at the local tip would make two nodes at
     * different heights reach different verdicts on identical bytes.
     *
     * A load fault is -2, not -1: "I could not read my committee" is the
     * ABSENCE of an answer, and reporting it as "this proof is invalid"
     * would blame a peer for this node's own broken database. */
    nodus_committee_member_t *committee = NULL;
    int c_count = 0;
    int lc_rc = load_committee_at_height_alloc(w, height, &committee, &c_count);
    if (lc_rc != 0) {
        free(committee);
        fprintf(stderr,
                "%s: VIEW_OK proof — CANNOT ESTABLISH THE COMMITTEE at "
                "height %llu (view=%u rc=%d%s); this node cannot decide\n",
                LOG_TAG, (unsigned long long)height, view, lc_rc,
                w->db ? "" : ", chain database not open");
        return -2;
    }
    if (c_count == 0) {
        /* The committed pre-genesis answer. There is no set to hash, so
         * step 2 cannot run — and a node with no committee at that height
         * is behind the evidence it is being shown. It has no verdict to
         * give. Deliberately NOT the gossip-roster fallback
         * verify_prepared_cert keeps: that exists for a proof shape which
         * carries no set hash, and this one does. */
        free(committee);
        fprintf(stderr,
                "%s: VIEW_OK proof — no committee at height %llu (view=%u, "
                "pre-genesis); no set to measure against, staying silent\n",
                LOG_TAG, (unsigned long long)height, view);
        return -2;
    }

    /* ── STEP 2 — the set hash must be BYTE-EQUAL ─────────────────────
     * A mismatch is -2, NOT -1. It says "I resolved a DIFFERENT committee
     * for this height, so I cannot judge this proof", which is a
     * different fact from "this proof is invalid": the proof may be
     * perfectly good under the set its signers saw. Calling it invalid
     * would let a node lagging one epoch boundary behind denounce
     * statements the rest of the cluster considers sound. */
    uint8_t local_set_hash[64];
    if (compute_committee_set_hash(committee, c_count, local_set_hash) != 0) {
        free(committee);
        fprintf(stderr,
                "%s: VIEW_OK proof — committee set-hash over %d members "
                "failed at height %llu; this node cannot decide\n",
                LOG_TAG, c_count, (unsigned long long)height);
        return -2;
    }
    if (memcmp(local_set_hash, set_hash, 64) != 0) {
        fprintf(stderr,
                "%s: VIEW_OK proof — COMMITTEE SET MISMATCH at height %llu "
                "(view=%u): carried %02x%02x%02x%02x%02x%02x%02x%02x…, "
                "resolved %02x%02x%02x%02x%02x%02x%02x%02x… over %d members. "
                "This node resolved a different set and cannot judge the "
                "proof; it is NOT reporting the proof invalid\n",
                LOG_TAG, (unsigned long long)height, view,
                set_hash[0], set_hash[1], set_hash[2], set_hash[3],
                set_hash[4], set_hash[5], set_hash[6], set_hash[7],
                local_set_hash[0], local_set_hash[1], local_set_hash[2],
                local_set_hash[3], local_set_hash[4], local_set_hash[5],
                local_set_hash[6], local_set_hash[7], c_count);
        free(committee);
        return -2;
    }

    /* ── STEPS 3-5 — membership, dedup, signature ─────────────────── */
    uint8_t preimage[NODUS_WITNESS_VIEWOK_PREIMAGE_LEN];
    uint32_t verified = 0;

    for (uint32_t i = 0; i < n_entries; i++) {
        const uint8_t *vid = entries[i].voter_id;

        /* STEP 4 — a duplicate voter counts ONCE. Without this, one
         * genuine statement repeated f+1 times would "prove" a view that
         * f+1 distinct members never asked for. Quadratic, over an array
         * bounded by NODUS_T3_MAX_WITNESSES — the same scan
         * verify_prepared_cert runs. */
        bool dup = false;
        for (uint32_t j = 0; j < i; j++) {
            if (memcmp(entries[j].voter_id, vid,
                       NODUS_T3_WITNESS_ID_LEN) == 0) {
                dup = true;
                break;
            }
        }
        if (dup) continue;

        /* STEP 3 — MEMBERSHIP AUTHORITY IS THAT COMMITTEE, FULL STOP.
         * The signer's key is resolved by matching SHA3-512(pubkey)
         * against voter_id, exactly as verify_prepared_cert does. A
         * non-member is SKIPPED, not fatal: an attacker could otherwise
         * void a sound proof simply by appending one junk entry to it. */
        const uint8_t *voter_pk = NULL;
        for (int ci = 0; ci < c_count; ci++) {
            nodus_key_t fp;
            if (qgp_sha3_512(committee[ci].pubkey, DNAC_PUBKEY_SIZE,
                              fp.bytes) == 0 &&
                memcmp(fp.bytes, vid, NODUS_T3_WITNESS_ID_LEN) == 0) {
                voter_pk = committee[ci].pubkey;
                break;
            }
        }
        if (!voter_pk) continue;

        /* STEP 5 — verify over the rebuilt 148-byte preimage carrying
         * THIS entry's voter_id. The voter_id is part of the signed
         * bytes, so the preimage tail is rewritten per entry; a signature
         * cannot be re-labelled under another member's id. */
        if (compute_view_ok_preimage(height, view, set_hash, vid,
                                       w->chain_id, preimage) != 0)
            continue;

        nodus_sig_t sig_in;
        nodus_pubkey_t pk_in;
        memcpy(sig_in.bytes, entries[i].signature, NODUS_SIG_BYTES);
        memcpy(pk_in.bytes, voter_pk, NODUS_PK_BYTES);
        if (nodus_verify_view_ok(&sig_in, preimage, sizeof(preimage),
                                   &pk_in) == 0)
            verified++;
    }

    /* ── STEP 6 — f+1 OF THAT COMMITTEE ───────────────────────────────
     *
     * WHY f+1 AND NOT A QUORUM. Each of these signatures certifies an
     * OUTCOME, not a vote. An honest node emits one only after observing
     * bft_vc_tally(target) >= bft_config.quorum over per-voter records
     * that each passed the committee-membership gate — so ONE honest
     * statement already testifies that 2f+1 committee members asked for
     * that view. With at most f Byzantine signers, f+1 DISTINCT
     * statements contain at least one honest one, and that one is
     * sufficient. Demanding a quorum of statements would require 2f+1
     * nodes to independently reach quorum before any of them could act,
     * which is a liveness cost bought for no additional safety.
     *
     * ⚠ HONEST LABEL: this rests entirely on the correctness of the tally
     * path it certifies. If an honest node could ever emit this statement
     * WITHOUT having observed quorum — or could emit two for the same
     * (height, view) — the f+1 argument collapses. That is the invariant
     * the producer side must preserve, and it is why the statement is an
     * outcome rather than a vote: a vote is re-emitted at every rung of
     * the escalation ladder, so accumulating votes would prove nothing.
     *
     * f DERIVATION — from the RESOLVED count, never from w->bft_config.
     * bft_config is the quorum in force NOW on THIS node; the signers
     * measured themselves against the committee governing `height`. Two
     * authorities for one decision disagree across every committee
     * change, which is the exact defect O15H C5 removed from
     * verify_prepared_cert (see its threshold comment above).
     *
     * The EXPRESSION is bft_vc_join_threshold's, with its one input
     * swapped: it computes ((quorum - 1) / 2) + 1 with a floor of 2, and
     * its comment (bft_vc_join_threshold, this file) proves that equals
     * f = (n-1)/3 exactly across the supported range — n=7 → quorum 5 →
     * 2+1, n=128 → quorum 86 → 42+1. It cannot be CALLED here because it
     * reads w->bft_config; deriving f from f_tolerance instead was
     * rejected there for a reason that applies here verbatim — that field
     * is a second copy of the same fact and a fixture that sets quorum
     * without it silently yields f+1 == 1, turning ONE Byzantine message
     * into an accepted proof. The floor of 2 is kept for the same
     * anti-amplification reason: below quorum 3 the formula degenerates
     * to 1, and one signature must never be a proof. */
    uint32_t q = dna_bft_quorum((uint32_t)c_count);
    uint32_t required = (q > 1) ? ((q - 1) / 2) + 1 : 0;
    if (required < 2) required = 2;

    free(committee);

    if (verified < required) {
        fprintf(stderr, "%s: VIEW_OK proof REJECTED (height=%llu view=%u "
                "verified=%u/%u required=%u committee=%d)\n", LOG_TAG,
                (unsigned long long)height, view, verified, n_entries,
                required, c_count);
        return -1;
    }
    return 0;
}

/* O15C-D.3 — THE PREPARED-VALUE LOCK.
 *
 * Returns true iff this node must REFUSE `tx_hash` at `height` because it
 * itself prepared a different value there.
 *
 * Why `last_prepared` and not `view_changes[]`: `view_changes[]` is a
 * node-local FIRST-2f+1 subset, frozen at quorum (a later VIEW_CHANGE for
 * the accepted view is dropped by the `vc->new_view <= current_view`
 * guard in handle_viewchg). Two honest nodes can therefore hold different
 * subsets permanently, and a node's own certificate can be missing from
 * its own subset entirely. `last_prepared` is the node's OWN
 * authenticated evidence — captured in handle_vote at the same moment it
 * observes prevote quorum, and persisted across restart in
 * pbft_state.last_prepared_blob — so it is the only input that cannot be
 * lost to message-delivery accidents.
 *
 * This is the refusal the quorum-intersection safety argument depends on.
 * PRECOMMIT is sent only on locally observed prevote quorum, and
 * `last_prepared` is captured in that same block, so PRECOMMITTER ⇒
 * CARRIER: any committed value has >= 2f+1 carriers, hence >= f+1 honest
 * carriers inside every quorum-sized set. With this lock each of those
 * refuses a conflicting value at that height, so a conflicting value
 * cannot reach quorum — which is what makes the fork unreachable.
 *
 * HEIGHT-GATED, deliberately: `last_prepared` is cleared on commit_batch
 * success but NOT on the sync/replay path (no reference in
 * nodus_witness_sync.c). A node that learned the block through SYNC would
 * otherwise carry a stale lock forever and reject every later proposal.
 * The caller-visible rule is therefore "only while we still hold an
 * uncommitted prepared value at exactly this height".
 *
 * NOT a redesign of PBFT: it enforces the rule the C5 machinery already
 * intends, using the evidence the node already has. */
bool nodus_witness_bft_prepared_lock_blocks(const nodus_witness_t *w,
                                              uint64_t height,
                                              const uint8_t *tx_hash) {
    if (!w || !tx_hash) return false;
    if (!w->last_prepared.present) return false;
    if (w->last_prepared.height != height) return false;
    return memcmp(w->last_prepared.tx_hash, tx_hash,
                  NODUS_T3_TX_HASH_LEN) != 0;
}

/* O15C-D.1 — C5 reproposal selection, in ONE place.
 *
 * Picks the highest-height prepared certificate out of the VIEW_CHANGE
 * records collected for the view just entered and binds this node to it;
 * clears the binding when no record carries one. Both the self-bind at
 * quorum and the leader's NEW_VIEW payload read the result, so a leader
 * can never broadcast a binding different from the one it enforces.
 *
 * ── O15C-D.2 — CANONICAL TOTAL ORDER (was: arrival-order first-wins) ─
 *
 * Selection key, strictly descending:
 *     (prepared.height, prepared.view, prepared.tx_hash)
 *
 * Each level has its OWN justification; they are not one arbitrary
 * tuple picked for convenience.
 *
 * 1. HEIGHT — unchanged primary rank. A later sequence number always
 *    dominates. Untouched by this season.
 *
 * 2. VIEW — the PBFT-canonical equal-rank discriminator. Castro-Liskov
 *    view-change selects, per sequence number, the prepared certificate
 *    with the HIGHEST VIEW. Ranking by height alone let an arrival-
 *    ordered pick return a cert from an EARLIER view, which can override
 *    a value prepared — and possibly committed — in a later one. So the
 *    old rule was a latent SAFETY hazard, not merely nondeterminism.
 *    `view` costs nothing to adopt: it is bytes [0..3] of the signed
 *    PREPARED preimage (compute_prepared_preimage above), so it is
 *    authenticated by the same 2f+1 signatures that admit the cert, and
 *    it is already populated on BOTH record paths — self-record from
 *    w->last_prepared.view, peer record from vc->prepared_view. No new
 *    field, no wire change, no version boundary.
 *
 * 3. TX_HASH (memcmp) — defense in depth ONLY. Two certs sharing
 *    (height, view) with DIFFERENT hashes would require two 2f+1 prevote
 *    sets in one view; those sets intersect in >= f+1 validators, so at
 *    least one honest validator would have prevoted twice in a single
 *    view. That is impossible with <= f Byzantine validators, so this
 *    level should never decide anything. It exists so the comparator is
 *    a TOTAL order regardless: the selection stays deterministic even if
 *    that assumption is ever broken, rather than silently reverting to
 *    arrival order at the exact moment the protocol is under attack.
 *
 * Why this ordering only became consensus-visible now: the first-wins
 * rule was written for the NEW_VIEW LEADER, which selected once and
 * broadcast its pick, so arrival order was node-local and consequence-
 * free by construction. O15C-D.1's self-bind made EVERY node run this
 * selection over its OWN arrival-ordered array — which is the moment the
 * ordering started deciding consensus state on more than one node.
 *
 * ⚠ SCOPE, stated honestly: this makes the selection deterministic for
 * nodes holding the SAME candidate set. Nodes whose first-2f+1
 * VIEW_CHANGE collections genuinely DIFFER can still bind differently
 * under any comparator — that is inherent to per-node selection over a
 * node-local subset, and resolving it is a NEW_VIEW-adoption design
 * question, filed separately in nodus/BUGS.md. */

/* Strictly-greater comparison on the canonical selection key above.
 * Returns true iff `a` outranks `b`. Pure; no witness state. */
static bool c5_cert_outranks(const nodus_witness_vc_record_t *a,
                               const nodus_witness_vc_record_t *b) {
    if (a->prepared.height != b->prepared.height)
        return a->prepared.height > b->prepared.height;
    if (a->prepared.view != b->prepared.view)
        return a->prepared.view > b->prepared.view;
    return memcmp(a->prepared.tx_hash, b->prepared.tx_hash,
                  NODUS_T3_TX_HASH_LEN) > 0;
}

void nodus_witness_bft_bind_reproposal_from_view_changes(nodus_witness_t *w) {
    if (!w) return;

    int best = -1;
    for (int i = 0; i < w->view_change_count; i++) {
        /* O15H D9 — ONLY records backing the target we are entering.
         *
         * This filter carries the safety property the old array-wipe
         * used to provide. Records now survive a target change (so that
         * one Byzantine message can no longer reset every honest node's
         * tally), which means the array can hold certificates attached
         * to LOWER targets — and letting one of those win this selection
         * is exactly the leak the wipe existed to prevent: a cert
         * admitted for view N binding the value proposed in view N+2.
         * Same guarantee, expressed as a question about each record
         * instead of as a destructive side effect. */
        if (w->view_changes[i].target_view != w->view_change_target) continue;
        if (!w->view_changes[i].prepared.has_prepared) continue;
        if (best < 0 ||
            c5_cert_outranks(&w->view_changes[i], &w->view_changes[best]))
            best = i;
    }

    if (best < 0) {
        w->reproposal_required = false;
        w->reproposal_height = 0;
        w->reproposal_prepared_view = 0;
        memset(w->reproposal_tx_hash, 0, NODUS_T3_TX_HASH_LEN);
        return;
    }

    w->reproposal_required = true;
    w->reproposal_height = w->view_changes[best].prepared.height;
    memcpy(w->reproposal_tx_hash, w->view_changes[best].prepared.tx_hash,
           NODUS_T3_TX_HASH_LEN);
    /* O15C-D.3 — remember the cert's view: it is the comparator's
     * equal-height discriminator when weighing a NEW_VIEW's carried
     * certificate against this binding, and it identifies the record
     * whose signatures we ship if we are the new leader. */
    w->reproposal_prepared_view = w->view_changes[best].prepared.view;

    fprintf(stderr, "%s: C5 self-bound to reproposal (height=%llu "
            "prepared_view=%u from view_changes[%d], current_view=%u)\n",
            LOG_TAG, (unsigned long long)w->reproposal_height,
            w->view_changes[best].prepared.view, best, w->current_view);
}

/* MED-28 — release the retained reproposal batch. */
void nodus_witness_retained_batch_clear(nodus_witness_t *w) {
    if (!w) return;
    for (int i = 0; i < w->retained_batch.count; i++) {
        if (w->retained_batch.entries[i]) {
            nodus_witness_mempool_entry_free(w->retained_batch.entries[i]);
            w->retained_batch.entries[i] = NULL;
        }
    }
    memset(&w->retained_batch, 0, sizeof(w->retained_batch));
}

/* MED-28 — MOVE the current round's batch into the reproposal holder
 * instead of freeing it. Called on round timeout, i.e. exactly when a
 * view change is about to start and a prepared cert may bind the next
 * view's first PROPOSE to this batch's tx_root.
 *
 * Ownership transfers: round_state is left with batch_count == 0 so the
 * subsequent round_state reset frees nothing. Only ONE batch is held —
 * a newer timeout supersedes an older one, matching the C5 rule that
 * binds to the HIGHEST prepared height. */
void nodus_witness_retained_batch_take(nodus_witness_t *w) {
    if (!w || w->round_state.batch_count <= 0) return;

    nodus_witness_retained_batch_clear(w);

    w->retained_batch.present = true;
    w->retained_batch.height = w->round_state.block_height;
    memcpy(w->retained_batch.tx_root, w->round_state.tx_root,
           NODUS_T3_TX_HASH_LEN);
    w->retained_batch.count = w->round_state.batch_count;
    for (int i = 0; i < w->round_state.batch_count; i++) {
        w->retained_batch.entries[i] = w->round_state.batch_entries[i];
        w->round_state.batch_entries[i] = NULL;
    }
    w->round_state.batch_count = 0;

    fprintf(stderr, "%s: MED-28 retained %d batch entries for reproposal "
            "(height=%llu)\n", LOG_TAG, w->retained_batch.count,
            (unsigned long long)w->retained_batch.height);
}

/* MED-28 — satisfy a NEW_VIEW reproposal binding from the retained
 * batch. See the declaration in nodus_witness_bft.h for the contract.
 *
 * Placed here, next to take/clear, because the three share the single
 * ownership invariant: exactly one owner of the entries at any moment. */
int nodus_witness_try_repropose_retained(nodus_witness_t *w,
                                           uint64_t height,
                                           const uint8_t *tx_root) {
    if (!w || !tx_root) return -1;

    if (!w->retained_batch.present ||
        w->retained_batch.height != height ||
        memcmp(w->retained_batch.tx_root, tx_root,
               NODUS_T3_TX_HASH_LEN) != 0) {
        /* We never saw the PROPOSE this view is bound to. Stay silent
         * and keep whatever we do hold: our round times out and rotates
         * the view to a leader that has the bytes. Standard PBFT
         * liveness — no safety rule is relaxed. */
        fprintf(stderr, "%s: MED-28 bound to a reproposal we do not hold "
                "(height=%llu) — staying silent so the view rotates\n",
                LOG_TAG, (unsigned long long)height);
        return -1;
    }

    /* Ownership moves to the round in one step: copy the pointers out,
     * empty the holder, then hand them over. The holder must be empty
     * BEFORE the call — start_round_from_entries can re-enter paths that
     * inspect witness state, and two owners of one entry is exactly the
     * double-free this repair exists to avoid. */
    nodus_witness_mempool_entry_t *entries[NODUS_W_MAX_BLOCK_TXS];
    int count = w->retained_batch.count;
    for (int i = 0; i < count; i++)
        entries[i] = w->retained_batch.entries[i];
    memset(&w->retained_batch, 0, sizeof(w->retained_batch));

    if (nodus_witness_bft_start_round_from_entries(w, entries, count) != 0) {
        /* The round refused the batch (not leader, round already active,
         * hash failure). We are now the only owner — release exactly
         * once. Dropping the retention here is deliberate: a binding we
         * cannot act on must not pin the entries forever. */
        fprintf(stderr, "%s: MED-28 reproposal round refused — releasing "
                "%d entries\n", LOG_TAG, count);
        for (int i = 0; i < count; i++)
            nodus_witness_mempool_entry_free(entries[i]);
        return -1;
    }

    /* O15C-D.1 — we ARE the node that satisfied the binding, and our own
     * PROPOSE never passes through handle_propose's C5 gate, so nothing
     * else would ever clear it. Left set, the stale binding would reject
     * the NEXT height's proposal on `next_bh != reproposal_height`. */
    w->reproposal_required = false;
    w->reproposal_height = 0;
    w->reproposal_prepared_view = 0;
    memset(w->reproposal_tx_hash, 0, NODUS_T3_TX_HASH_LEN);

    fprintf(stderr, "%s: MED-28 re-proposed retained batch (%d entries, "
            "height=%llu) — own C5 binding satisfied\n", LOG_TAG, count,
            (unsigned long long)height);
    return 0;
}

/* Free any heap-allocated batch entries in round_state */
static void round_state_free_batch(nodus_witness_round_state_t *rs) {
    for (int i = 0; i < rs->batch_count; i++) {
        if (rs->batch_entries[i]) {
            nodus_witness_mempool_entry_free(rs->batch_entries[i]);
            rs->batch_entries[i] = NULL;
        }
    }
    rs->batch_count = 0;
}

/* Emit client responses for the round currently held in round_state and free
 * the batch. Idempotent — if batch_count == 0 this is a no-op.
 *
 * Split out from handle_vote precommit→commit path so that handle_commit can
 * also call it when the leader ends up committing its own round via the
 * remote-COMMIT fast path (non-leader peer reached precommit quorum first and
 * broadcast COMMIT before our handle_vote accumulated its own quorum). Without
 * this, forwarded client spends on the leader node silently drop the
 * w_fwd_rsp reply, and the original client times out at 60s even though the
 * TX committed on-chain in ~1 second.
 *
 * `status` is a DNAC spend-result status: DNAC_STATUS_APPROVED on the two
 * commit paths, DNAC_STATUS_ERROR when the leader's own batch failed and
 * the block was rolled back. `error_msg` MUST be non-NULL for any
 * non-APPROVED status — see the guard below. */
static void bft_emit_batch_replies(nodus_witness_t *w, int status,
                                    const char *error_msg) {
    if (!w || w->round_state.batch_count <= 0)
        return;

    /* Fail close on the send_spend_result contract: its error branch is
     * `if (status != DNAC_STATUS_APPROVED && error_msg)`
     * (nodus_witness_handlers.c:2161) — a non-APPROVED status with a NULL
     * message falls THROUGH that branch and still emits the signed
     * receipt. Never let that combination reach the sender. */
    if (status != DNAC_STATUS_APPROVED && !error_msg)
        error_msg = "consensus error";

    fprintf(stderr, "%s: emitting client replies for round %lu (%d entries, "
            "status=%d)\n",
            LOG_TAG, (unsigned long)w->round_state.round,
            w->round_state.batch_count, status);

    for (int bi = 0; bi < w->round_state.batch_count; bi++) {
        nodus_witness_mempool_entry_t *e = w->round_state.batch_entries[bi];
        if (!e) continue;

        if (e->client_conn && !e->is_forwarded) {
            nodus_witness_send_spend_result(w, e, status, error_msg);
        } else if (e->is_forwarded) {
            int fwd_pi = -1;
            for (int pi = 0; pi < w->peer_count; pi++) {
                if (memcmp(w->peers[pi].witness_id,
                           e->forwarder_id,
                           NODUS_T3_WITNESS_ID_LEN) == 0 &&
                    w->peers[pi].conn && w->peers[pi].identified) {
                    fwd_pi = pi;
                    break;
                }
            }
            if (fwd_pi < 0) {
                fprintf(stderr, "%s: batch fwd_rsp: forwarder not found "
                        "(peers=%d, fid=", LOG_TAG, w->peer_count);
                for (int k = 0; k < 4; k++)
                    fprintf(stderr, "%02x", e->forwarder_id[k]);
                fprintf(stderr, ")\n");
            } else {
                nodus_t3_msg_t fwd_rsp;
                memset(&fwd_rsp, 0, sizeof(fwd_rsp));
                fwd_rsp.type = NODUS_T3_FWD_RSP;
                fwd_rsp.txn_id = ++w->next_txn_id;
                snprintf(fwd_rsp.method, sizeof(fwd_rsp.method),
                         "w_fwd_rsp");
                /* Non-zero status makes the forwarder emit a T2 error to
                 * the original client instead of a receipt
                 * (nodus_witness_peer.c:969-987). */
                fwd_rsp.fwd_rsp.status = (uint32_t)status;
                memcpy(fwd_rsp.fwd_rsp.tx_hash, e->tx_hash,
                       NODUS_T3_TX_HASH_LEN);
                /* Phase 13 / Task 13.2 — populate full receipt fields so
                 * the forwarder can pass them through to the client
                 * instead of the legacy hardcoded 0/0. */
                fwd_rsp.fwd_rsp.block_height = e->committed_block_height;
                fwd_rsp.fwd_rsp.tx_index = e->committed_tx_index;
                memcpy(fwd_rsp.fwd_rsp.chain_id, w->chain_id, 32);
                fill_header(w, &fwd_rsp.header);
                uint8_t fwd_buf[NODUS_T3_MAX_MSG_SIZE];
                size_t fwd_len = 0;
                if (nodus_t3_encode(&fwd_rsp, &w->server->identity.sk,
                                     fwd_buf, sizeof(fwd_buf),
                                     &fwd_len) == 0) {
                    nodus_tcp_send(w->peers[fwd_pi].conn, fwd_buf, fwd_len);
                    fprintf(stderr, "%s: sent w_fwd_rsp to forwarder peer %d "
                            "for tx_hash ", LOG_TAG, fwd_pi);
                    for (int k = 0; k < 4; k++)
                        fprintf(stderr, "%02x", e->tx_hash[k]);
                    fprintf(stderr, "\n");
                }
            }
        }
    }

    round_state_free_batch(&w->round_state);
}

/* ── O15I P3 — the demand-armed follower deadman's helpers ─────────── */

/**
 * O15J C — THE per-entry question, in ONE place: can this entry still be
 * included in a block?
 *
 * BOTH P3 helpers below need it. P3(a) asks it to decide whether anything
 * is worth rotating the view for; P3(b) asks it to decide what is worth
 * putting on the wire. A second open-coded copy is exactly how the two
 * would fall out of step — the same drift nodus_witness.h warns about for
 * the reaper and the demand predicate, which is why that pair shares
 * nodus_witness_v2_entry_is_decided rather than each listing the verdicts.
 *
 * THE RULE, one branch per entry shape:
 *   - nullifier_count == 0 (the successor class-200 envelope shape, and a
 *     legacy entry with no inputs): the O15I V1 verdict, collapsed through
 *     the SHARED nodus_witness_v2_entry_is_decided the reaper also uses;
 *   - a class-201 CLAIM: the SPENT-CLAIM table, because that is where a
 *     claim's nullifier is actually committed — O15K V-3, added below,
 *     and the ONE rule here that did not come across unchanged from what
 *     bft_p3_live_demand applied inline. Everything else did;
 *   - otherwise: the committed-nullifier walk, the identical test batch
 *     selection applies before proposing.
 *
 * The reaper (nodus_witness_mempool_evict_committed) carries the same V-3
 * routing, and the two MUST keep agreeing for the reason this function
 * exists in one place at all: what the reaper deletes must not be what
 * this predicate calls demand.
 *
 * It is deliberately NOT the reaper's two-step (nullifiers, THEN verdict
 * as a second opinion). Widening it here would change P3(a)'s firing
 * behaviour, which is not what O15J is about; the reaper stays the more
 * thorough of the two and is the one that actually deletes.
 *
 * Deterministic and node-local: entry bytes plus this node's own committed
 * state, no clock and no message. FAIL-CLOSED in the KEEP direction —
 * anything this node cannot judge answers false ("still live"), which for
 * a liveness trigger is the conservative side.
 */
static bool bft_p3_entry_finished(nodus_witness_t *w,
                                  const nodus_witness_mempool_entry_t *e) {
    if (!e) return true;            /* nothing to include, nothing to send */

    if (e->nullifier_count == 0)
        return nodus_witness_v2_entry_is_decided(
                   nodus_witness_v2_entry_verdict(w, e->tx_data, e->tx_len));

    /* ⚠ O15K V-3 — A CLASS-201 CLAIM IS ASKED OF A DIFFERENT TABLE, AND
     * ASKING THE WRONG ONE IS THE WHOLE DEFECT. A claim's nullifier is
     * committed to `v2_claims_spent` (nodus_witness_v2_claims.c, the
     * INSERT on the commit path). The walk below reads the LEGACY
     * `nullifiers` table, whose only writer is the legacy commit path a
     * successor commit bypasses — so a settled claim can NEVER appear
     * there. And the other half says nothing either: the class gate in
     * nodus_witness_v2_entry_verdict answers UNJUDGED for a 201. Both
     * halves therefore answer "not decided", the entry reads as live
     * demand forever, and P3 keeps rotating the view against a perfectly
     * healthy leader — the O15I V1 shape re-entering through the claim
     * door, in a lane whose own comments assert it is closed.
     *
     * ROUTED BY CLASS, and only by class: every other entry keeps the
     * legacy walk below character-identical. nodus_witness_nullifier_exists
     * is deliberately NOT taught about this table — merging the two
     * namespaces could answer "spent" to the legacy double-spend path for
     * a nullifier that was never a legacy input, which is worse than the
     * bug being fixed here.
     *
     * Reached only with nullifier_count > 0, so nullifiers[0] is the
     * committed nullifier both intakes re-derive before pooling a 201
     * (nodus_witness_peer.c / nodus_witness_handlers.c, fail-closed: a
     * derivation failure pools nothing). The zero-count shape keeps the
     * verdict branch above, untouched.
     *
     * ⚠ ONLY == 1 COUNTS AS FINISHED, AND THAT IS NOT A STYLE CHOICE.
     * The helper is a TRI-STATE — 1 spent, 0 not spent, -1 DB fault — and
     * this function's contract is FAIL-CLOSED IN THE KEEP DIRECTION:
     * anything this node cannot judge answers "still live". So 0 and -1
     * both map to false. A -1 mapped to "finished" would silently drop a
     * client's pending work out of the demand this node is willing to
     * rotate for, on nothing more than a busy database.
     *
     * ⚠ THE SAME HELPER MAPS -1 THE OPPOSITE WAY AT THE ADMISSION CALL
     * SITE, and the two must never be collapsed into one. There it is
     * deciding whether to ADMIT, so an unknown answers "spent" and the
     * transaction is REJECTED — never admit a possible double-spend. Here
     * it is deciding whether an entry may stop counting as demand, so an
     * unknown answers "still live" — never discard a client's pending
     * work. One fact, two questions, opposite safe answers; that is
     * exactly why the helper returns the tri-state instead of a bool and
     * leaves the mapping to each caller.
     *
     * ⚠ AND NOTE THE ASYMMETRY WITH THE BRANCH BELOW, stated because it
     * is surprising rather than because this change introduces it:
     * nodus_witness_nullifier_exists is fail-closed toward SPENT (a DB
     * fault returns true, nodus_witness_db.c — "assuming spent"), so on a
     * fault the legacy branch answers "finished" while this one answers
     * "still live". That is pre-existing behaviour on a shipped
     * double-spend guard and O15K deliberately does not touch it; it is
     * recorded here so the next reader does not "align" the two by
     * flipping the direction this comment exists to protect. */
    /* ⚠ WALK EVERY NULLIFIER, exactly as the reaper does
     * (nodus_witness_mempool_evict_committed). Both intakes pin a
     * class-201 entry's count to 1 today (nodus_witness_peer.c and
     * nodus_witness_handlers.c re-derive the ONE committed nullifier),
     * so index 0 would be sufficient — but this predicate and the reaper
     * answer the SAME question, and nodus_witness.h states they must keep
     * agreeing. Checking only slot 0 here would make them diverge the day
     * a 201 carries more than one: the reaper would evict the entry while
     * this predicate still called it live demand, which is the V-3 shape
     * returning through the door V-3 just closed. Same loop, same
     * `== 1`-only rule, no drift. */
    if (e->tx_type == NODUS_W_TX_V2_CLAIM) {
        for (int j = 0; j < e->nullifier_count; j++) {
            if (nodus_witness_v2_claim_nullifier_spent(w, e->nullifiers[j]) == 1)
                return true;
        }
        return false;
    }

    for (int j = 0; j < e->nullifier_count; j++) {
        if (nodus_witness_nullifier_exists(w, e->nullifiers[j]))
            return true;
    }
    return false;
}

/**
 * P3(a) — is there demand this node could still be waiting on?
 *
 * "Demand" is not "the mempool is non-empty". An entry whose nullifier
 * the chain has already committed can never be included again — the
 * leader's own batch selection drops it on sight — so treating it as a
 * reason to rotate the view would let a settled transaction drive
 * rotations forever. The predicate here is therefore the SAME one batch
 * selection uses, applied from the follower's side.
 *
 * Called ONLY at the would-fire point, never on the common path: it can
 * cost up to NODUS_W_MAX_MEMPOOL x NODUS_T3_MAX_TX_INPUTS indexed point
 * lookups plus, for a successor class-200 entry, an intent derivation —
 * and the first live entry short-circuits it. The window re-stamp at the
 * call site bounds it to once per round_timeout_ms.
 *
 * O15I V1 — A ZERO-NULLIFIER ENTRY IS NOT AUTOMATICALLY LIVE. It used to
 * be, and that was the defect: a successor class-200 envelope is pooled
 * with nullifier_count == 0 (nodus_witness_peer.c skips the legacy
 * nullifier walk on a successor), NOTHING on a follower could ever remove
 * one, and this predicate answered "live" for it unconditionally. One
 * finished envelope in one follower's pool therefore initiated a view
 * change every round_timeout_ms, forever, against a perfectly healthy
 * leader on a quiet chain — and with 1 < f+1 nobody joined, so the node
 * escalated inside VIEW_CHANGE while handle_propose refused every
 * proposal. Such an entry is now judged by
 * nodus_witness_v2_entry_verdict, collapsed through the SHARED
 * nodus_witness_v2_entry_is_decided the reaper also uses — so the two
 * agree by construction: what the reaper deletes is not demand, and what
 * it keeps is.
 *
 * FINISHED covers three shapes, and all three matter here: the intent is
 * already committed, the envelope has EXPIRED (an expiry_height below the
 * candidate; the tip only advances, so it can never come back), or the
 * bytes no longer decode. None of them can ever be included by any node,
 * so counting them as demand would be asking the cluster to rotate the
 * view on behalf of a transaction that cannot exist.
 *
 * Everything this node genuinely cannot judge — a legacy chain, a
 * class-201 claim, a missing domain, an ERR_HASH node fault — answers
 * UNJUDGED and therefore still counts as LIVE, which is the conservative
 * direction for a liveness trigger.
 *
 * A pending FORWARD counts as live unconditionally: a client is provably
 * waiting on an answer this node cannot produce, and the forward slot
 * retains no transaction bytes to judge (nodus_witness.h — it carries
 * tx_hash and routing only).
 *
 * ⚠ O15J C — THE PER-ENTRY RULE EVERYTHING ABOVE DESCRIBES NOW LIVES IN
 * bft_p3_entry_finished, unchanged, because P3(b) needs the identical
 * question answered and a second copy would drift. What stays here is
 * this function's OWN two rules: the pending-forward short-circuit, and
 * "one live entry is enough".
 *
 * ⚠ AND NOTE WHAT O15J A CHANGED ABOUT THE INPUT, not about this code: a
 * non-leader now POOLS the client's entry before forwarding
 * (nodus_witness_pool_local_demand), so on the node a client is actually
 * talking to `mempool.count` is no longer 0 while a pending_forwards slot
 * carries the only trace of the request. That is the whole point — this
 * predicate could not see a waiting client before, because neither half
 * of its input existed once the forward failed.
 */
static bool bft_p3_live_demand(nodus_witness_t *w) {
    if (w->pending_forward_count > 0) return true;

    for (int i = 0; i < w->mempool.count; i++) {
        const nodus_witness_mempool_entry_t *e = w->mempool.entries[i];
        if (!e) continue;
        /* The first live entry short-circuits, exactly as before — which
         * is what bounds the class-200 derivation cost documented above. */
        if (!bft_p3_entry_finished(w, e)) return true;
    }
    return false;
}

/**
 * P3(b) — DEMAND DISSEMINATION, at the deadman's fire and nowhere else.
 *
 * A forwarded transaction goes to the LEADER only, so when the leader is
 * dead the demand exists on exactly one node. That is why P3(a) alone
 * fixes nothing: the one node holding the work initiates a view change,
 * and 1 is far below the f+1 join threshold, so nobody joins it. This
 * puts the bytes on every peer, which is what makes the rotation
 * meaningful — whoever the next leader turns out to be already holds the
 * work when it gets there.
 *
 * NOT AT INTAKE. Steady-state forwarding traffic is unchanged; this runs
 * at most once per round_timeout_ms, and only on a node that has already
 * observed the committed tip frozen for a full round with live demand.
 *
 * ⚠ O15K §3.3 — NO LONGER SCOPED TO SUCCESSOR CHAINS, AND THE CONTRACT
 * THAT SCOPED IT CHANGED IN THE SAME COMMIT. What stood here was:
 *
 *     "SCOPED TO SUCCESSOR CHAINS, matching the intake side. On a
 *      successor the receiving non-leader runs the full ADMISSION lane
 *      before pooling (nodus_witness_peer.c). On a LEGACY chain that
 *      intake is structural-only — a nullifier walk, no signature
 *      verification — so a legacy peer still refuses a non-leader
 *      forward byte-identically, and broadcasting there would be n-1
 *      copies of a transaction that every recipient discards. Legacy
 *      recovers through the rotation itself: once a live leader is
 *      elected, the ordinary client retry reaches it."
 *
 * It is quoted rather than deleted because a reader has to be able to
 * see WHICH premise moved, and that the scoping was reasoned rather
 * than accidental.
 *
 * THE PREMISE MOVED. The legacy non-leader refusal in
 * nodus_witness_peer_handle_fwd_req is opened, and the verify that
 * legacy intake never had is added at that same door, ahead of
 * mempool_add (O15K §3.2). A legacy recipient now POOLS the copy instead
 * of discarding it, and pools nothing it has not verified — which is
 * what makes broadcasting here safe rather than merely useful. That gate
 * and this function are one change: neither is correct without the
 * other, and shipping this half alone would put unverified bytes into
 * n-1 mempools.
 *
 * AND THE LAST SENTENCE WAS NEVER TRUE. "Legacy recovers through the
 * rotation itself" ASSUMES A ROTATION, and on legacy there is none to
 * recover through. The demand lives on the single node that forwarded it
 * (first paragraph above) while bft_vc_join_threshold floors the join at
 * 2, so the lone firer escalates alone until P1 releases it, the leader
 * stays pinned by (epoch + view) % n over a tip that cannot move, and
 * the client retry that sentence relied on lands on the same dead node
 * forever. That is the O15K halt as recorded: eight healthy nodes, ~5
 * minutes, and not one view-change line on any of them.
 *
 * ⚠ DISSEMINATION IS ALSO WHAT MAKES STAGGERED DEADMEN CONVERGE — a
 * determinism property, not merely a delivery one, and worth stating
 * because nothing else in the design supplies it. Every node's window is
 * node-local (DG-5), so nodes reach the would-fire point at different
 * instants; and a peer with an EMPTY pool is not merely late, it is not
 * armed at all, because the no-demand branch of the P3 arm clears its
 * window outright. Receiving this broadcast gives it demand, so its next
 * tick takes the arm's first-observation branch and stamps the window at
 * that moment: every empty-pool recipient's clock therefore starts when
 * the FIRST firer spoke, and they mature one round_timeout_ms later
 * TOGETHER, which is how f+1 assembles out of unsynchronised timers. A
 * recipient that already held demand keeps its own running window and is
 * NOT re-synchronised — it was already counting, and does not need to
 * be. Nothing here branches on a clock, draws randomness, or depends on
 * iteration order: DG-8 still holds, this loop's only output is a set of
 * messages and never consensus state.
 *
 * ⚠ WHY THE SURGE EXEMPTION IS THIS FUNCTION'S PROBLEM (O15K §3.3a,
 * DG-3). The admission verdict carries exactly one node-local term — the
 * fee floor scaled by mempool.count / NODUS_W_FEE_SURGE_STEP (8). This
 * function deliberately fills every peer's pool with the SAME demand, so
 * charging replicated bytes that surcharge would throttle the recovery
 * precisely as it spreads: past the step the floor doubles, fresh client
 * demand is refused cluster-wide, and the nodes that just received the
 * rebroadcast never arm. Replicated intake is therefore not charged the
 * queue-depth surcharge, while a direct client submission still is. That
 * decision is implemented at the intake door and not here — but this
 * function is the reason it has to exist.
 *
 * IT ADDS NO AUTHORITY. The T3 sender must already be in the roster to
 * be dispatched at all, the transaction is re-verified at intake before
 * anything can be pooled — on BOTH lanes now (§3.2), with the one
 * node-local surcharge above deliberately not applied to replicated
 * bytes — and NODUS_W_MAX_MEMPOOL bounds what a recipient can be made to
 * hold.
 *
 * REPLY ROUTING is carried, not invented. A committing leader answers
 * fwd_req by sending w_fwd_rsp to `forwarder_id`
 * (bft_emit_batch_replies). An entry we ourselves received as a forward
 * already names the node holding the client connection, so its
 * forwarder_id is preserved verbatim. An entry we took directly from a
 * client (client_conn set — we were the leader when it arrived) names
 * US, because no other node knows that client.
 *
 * ⚠ RESIDUAL, deliberately not papered over: for that second kind we do
 * NOT register a pending_forwards slot, so if a remote leader commits
 * it, the w_fwd_rsp finds no slot and is logged and dropped — that
 * client gets no receipt on this connection. Registering a slot would be
 * worse: when WE commit the entry ourselves the client gets its receipt
 * from send_spend_result AND a spurious NODUS_ERR_TIMEOUT from the
 * unclaimed slot 30 s later. The pre-P3 behaviour for the same client
 * was that the transaction never committed at all, so this is strictly
 * better for the chain and no worse for the client.
 *
 * ⚠ O15J A ADDS A THIRD KIND, and the same residual covers it — stated
 * rather than discovered later. A non-leader now pools the client's entry
 * itself (nodus_witness_pool_local_demand), ORPHANED: client_conn NULL,
 * is_forwarded true, forwarder_id = OUR id. So the branch below carries
 * our id, which is correct — we are the node that held the client
 * connection. But that client was ALREADY answered synchronously at
 * intake (the O15J B message on the unreachable-leader path, or a
 * w_fwd_rsp routed through a pending_forwards slot on the ordinary path),
 * and the slot was released either way. If a remote leader later commits
 * this entry, its w_fwd_rsp therefore finds no slot and is logged and
 * dropped, exactly as above. That is the intended shape: the client's
 * receipt is its retry against the committed chain, and the alternative —
 * a slot pinned open across a whole view change — is the spurious-timeout
 * failure the paragraph above rejects.
 */
static void bft_p3_broadcast_demand(nodus_witness_t *w) {
    /* O15K §3.3 — THE `if (!w->v2_successor) return;` THAT STOOD HERE IS
     * GONE, and its absence is the fix. It made this function a no-op on
     * the one lane the halt actually happened on, while NOTHING else in
     * P3 is successor-scoped: the arm (mempool.count / pending_forwards),
     * bft_p3_live_demand and the fire gate all run on legacy today. So a
     * legacy node could already START a view change with the single step
     * that lets anyone JOIN it switched off — the lone rotation of
     * O15K §0.5, which 1 < f+1 guarantees nobody joins. Dissemination is
     * that step, and it now runs on both lanes. */

    /* ONE message object for the whole loop. nodus_t3_msg_t's union is
     * dominated by NEW_VIEW's 128-slot certificate array, so it is a
     * large stack object; every other producer in this file declares
     * exactly one (initiate_view_change, bft_emit_batch_replies), and
     * hoisting it out of the loop keeps that property here too. */
    nodus_t3_msg_t fwd;
    int sent = 0;
    int skipped = 0;
    for (int i = 0; i < w->mempool.count; i++) {
        nodus_witness_mempool_entry_t *e = w->mempool.entries[i];
        if (!e || !e->tx_data || e->tx_len == 0) continue;

        /* O15J C — DO NOT DISSEMINATE WHAT THE CHAIN HAS ALREADY
         * DECIDED, judged by the SAME per-entry rule bft_p3_live_demand
         * applies (bft_p3_entry_finished — the committed-nullifier walk,
         * or the O15I V1 verdict for a zero-nullifier entry).
         *
         * This is a HONESTY fix, not a safety one, and it is worth saying
         * which: every recipient already refuses these at its own
         * admission gate, so the pre-existing behaviour was WASTE rather
         * than danger. But it was waste with a misleading shape — a
         * follower whose pool had settled would emit n-1 copies of
         * finished work at every fire, and the quiet-chain traffic story
         * has to match what the code does.
         *
         * The cost is bounded the same way live_demand's is: this runs
         * ONLY at the would-fire point, at most once per
         * round_timeout_ms. Unlike live_demand it does not short-circuit
         * on the first live entry, so the worst case is one verdict
         * derivation per pooled class-200 entry — the same bound
         * nodus_witness_mempool_evict_committed already accepts, and the
         * loop was already doing NODUS_W_MAX_MEMPOOL broadcasts. */
        if (bft_p3_entry_finished(w, e)) { skipped++; continue; }

        memset(&fwd, 0, sizeof(fwd));
        fwd.type = NODUS_T3_FWD_REQ;
        fwd.txn_id = ++w->next_txn_id;
        memcpy(fwd.fwd_req.tx_hash, e->tx_hash, NODUS_T3_TX_HASH_LEN);
        fwd.fwd_req.tx_data = e->tx_data;
        fwd.fwd_req.tx_len = e->tx_len;
        fwd.fwd_req.client_pubkey = e->client_pubkey;
        fwd.fwd_req.client_sig = e->client_sig;
        fwd.fwd_req.fee = e->fee;
        memcpy(fwd.fwd_req.forwarder_id,
               e->is_forwarded ? e->forwarder_id : w->my_id,
               NODUS_T3_WITNESS_ID_LEN);

        /* The ordinary broadcast: it fills and signs the header and
         * sends to every connected identified peer, exactly as PROPOSE
         * and COMMIT do. */
        if (nodus_witness_bft_broadcast(w, &fwd) > 0)
            sent++;
    }

    if (sent > 0 || skipped > 0)
        fprintf(stderr, "%s: P3 re-broadcast %d/%d mempool entries to the "
                "peer set (%d already decided, not sent) — the dead leader "
                "is not the only node that may hold this work\n",
                LOG_TAG, sent, w->mempool.count, skipped);
}

void nodus_witness_bft_check_timeout(nodus_witness_t *w) {
    if (!w) return;

    /* P1 — MOOT-ROUND RELEASE. The missing sibling of the two other
     * height-based releases this same tick already performs: the MED-28
     * retained batch (nodus_witness.c:1128-1134) and the C5 reproposal
     * binding (nodus_witness.c:1141-1150). Same trigger — "the chain has
     * reached the height this object was about" — and the same
     * semantics: the object is now unusable, so let it go.
     *
     * THE HOLE IT CLOSES. handle_propose refuses every proposal while
     * the phase is not IDLE (:4503-4507). The only phase->IDLE reset on
     * the remote-COMMIT path is gated on `round_state.round ==
     * hdr->round` (:6254-6257), and handle_commit itself has NO phase
     * gate — so a node whose round number has fallen behind keeps
     * applying remote commits (its DB tip advances normally) while its
     * phase stays pinned. On the 20-node rehearsal three validators sat
     * at DB tip 42 with round_state.block_height frozen at 36 and phase
     * 5, rejecting every PROPOSE; the participating set dropped below
     * quorum and the chain halted for good. A view change that never
     * assembles quorum reaches the same trap from the other direction:
     * from VIEW_CHANGE the escalation branch below re-arms forever and
     * never returns to IDLE.
     *
     * THE CONDITION IS THE DEFINITION OF MOOT. `block_height` is the
     * height this round / view change is trying to decide. Once our OWN
     * committed chain contains that height, there is nothing left to
     * decide: the outcome is already final and already ours.
     * `block_height != 0` keeps a zeroed round_state (a node that has
     * never run a round) from matching the empty-chain tip of 0.
     *
     * WHY IT IS SAFE.
     *  - The trigger is our own committed chain. That decision is final
     *    and purely local, so no peer's message and no timing can make
     *    two honest nodes evaluate it differently at the same height.
     *  - No vote is emitted here and none is retracted: votes are
     *    broadcast messages, and dropping local round state does not
     *    unsay one. A later PROPOSE builds a fresh round from scratch
     *    (:4620-4645), which overwrites every field cleared here.
     *  - `current_view` is NOT touched. As of O15N Faz 2C2 it is written
     *    in exactly TWO places — bft_viewok_apply in this file, on a
     *    verified VIEW_OK proof, and nodus_witness_db.c's restore of this
     *    node's own previously proven value. The three unproven writes
     *    that used to sit beside them (the PROPOSE copy, the view-change
     *    quorum self-advance and the NEW_VIEW `>` accept) are gone, and
     *    the IDENT adoption was DELETED in v0.19.24. Neither survivor is
     *    here. Leader election therefore sees no change, so this can
     *    neither invent a leader nor skip one.
     *  - `view_changes[]`, `last_prepared`, `reproposal_*` and
     *    `retained_batch` are deliberately left alone: each has its own
     *    lifecycle (last_prepared is cleared by commit at :8419 and by
     *    after_successor_commit at :5115; the other two by the height
     *    guards in the tick cited above). Clearing them here would
     *    destroy a prepared certificate that a later view may still
     *    have to honour — the C5 safety property.
     *  - round_state_free_batch is the same release the round-timeout
     *    branch below already performs on the same entries (:7975); this
     *    only reaches it sooner, and only for a height whose block is
     *    already committed. */
    if (w->round_state.phase != NODUS_W_PHASE_IDLE &&
        w->round_state.block_height != 0) {
        /* The two cheap field tests gate the query, so an IDLE node —
         * the common case, every tick — still costs no DB round trip. */
        uint64_t committed_tip = nodus_witness_block_height(w);
        if (committed_tip >= w->round_state.block_height) {
            fprintf(stderr, "%s: P1 round at height %llu superseded by "
                    "committed chain (tip=%llu, phase=%d) — releasing "
                    "to IDLE\n", LOG_TAG,
                    (unsigned long long)w->round_state.block_height,
                    (unsigned long long)committed_tip,
                    w->round_state.phase);
            round_state_free_batch(&w->round_state);
            w->round_state.phase = NODUS_W_PHASE_IDLE;
            w->round_state.client_conn = NULL;
            w->view_change_in_progress = false;
            w->view_change_voted = false;
            /* Return rather than fall through: the IDLE branch below
             * would now match and log an "idle_stall" diagnostic
             * describing a stall that just ended. */
            return;
        }
    }

    if (w->round_state.phase == NODUS_W_PHASE_IDLE) {
        /* ── O15I P2 — POST-VIEW-CHANGE PROPOSE-WAIT DEADMAN, FIRE ─────
         *
         * The one timeout an IDLE node may arm, and the reason this
         * branch is no longer an unconditional dead end. It is armed
         * ONLY in the aftermath of a COMPLETED view change and only on a
         * non-leader (see the arm site in bft_vc_check_quorum), so a
         * quiet healthy chain never reaches the body below and there is
         * no idle view churn.
         *
         * O15I V2 — THE CONSENSUS-ACTIVE GATE COMES FIRST, and it is not
         * belt-and-braces. nodus_witness_bft_config_init leaves
         * round_timeout_ms AND viewchg_timeout_ms at 0 whenever
         * n < NODUS_T3_MIN_WITNESSES (:414-419), and bft_config is not
         * initialised at witness creation at all — so a calloc'd witness
         * carries all-zero until the first refresh. This function has no
         * consensus-active guard of its own and the tick calls it
         * unconditionally, so with a zero config an armed deadline is
         * ALREADY expired and this site would fire on the very first
         * one-second boundary, then escalate every second (the VIEW_CHANGE
         * branch's budget is 0 too). nodus_witness_bft_consensus_active is
         * the predicate that already decides whether this node may run
         * consensus at all (:457, quorum > 0 — the same test that gates
         * round start at :3944); a node that may not run a round must not
         * rotate the view either.
         *
         * ORDER OF THE TESTS IS DELIBERATE, cheapest first: this runs on
         * every tick (~20x/s) for every witness, and
         * nodus_witness_bft_is_leader costs a committee load plus a
         * SHA3-512 per member. The gate and the armed test are one field
         * load each and together short-circuit every node on a healthy
         * chain.
         *
         * THE is_leader RE-CHECK is not redundant with the arm-side one:
         * `current_view` can still move under an IDLE node between the
         * two — as of O15N Faz 2C2 the remaining way is a verified
         * VIEW_OK proof arriving in bft_viewok_apply (handle_newview's
         * accept, which this used to cite, no longer writes the view;
         * the IDENT adoption was DELETED in v0.19.24).
         * A node that became the leader in the meantime must SEND rather
         * than rotate away from its own view. Such a node stays armed
         * and harmless: it disarms at its next commit, PROPOSE, or VC.
         *
         * `time_ms()` has one-second granularity (:105), so `>` means
         * the full round_timeout_ms has genuinely elapsed — the same
         * comparison the round timeout below uses.
         *
         * THE CLOCK RE-STAMP IS KEPT, and it is not decoration.
         *
         * O15M made initiate_view_change stamp phase_start_time itself,
         * beside the write that moves the phase to VIEW_CHANGE, so the
         * invariant "while the phase is VIEW_CHANGE, phase_start_time is
         * the age of the CURRENT target's window" no longer depends on
         * every caller remembering. That covers the ordinary path from
         * here. What it does not cover is the case where
         * initiate_view_change returns at its early return without
         * reaching its own stamp — the dead-episode flags described at
         * the round-timeout site below — and this stamp is what still
         * bounds the escalation's budget then. The adoption block in
         * handle_viewchg stamps only when the phase is ALREADY
         * VIEW_CHANGE (:7610-7611), which it is not here: we are
         * entering from IDLE. Without a stamp on either side, the
         * VIEW_CHANGE branch above would measure this view change's age
         * from a round that ended long ago and escalate the target on
         * the very next tick, forever: the O15H D2 defect, re-entered
         * through a new door. The round-timeout path below keeps its
         * stamp for the identical reason.
         *
         * The HEIGHT anchor needs nothing here — initiate_view_change's
         * P1(a) normalization re-anchors a stale IDLE round_state at
         * tip+1 (:6534-6538), which is precisely the case this fire site
         * hands it.
         *
         * TARGET is the ordinary current_view + 1: initiate_view_change
         * picks it, and this path invents no rule of its own. */
        if (nodus_witness_bft_consensus_active(w) &&
            w->awaiting_propose_deadline_ms != 0 &&
            time_ms() > w->awaiting_propose_deadline_ms &&
            !nodus_witness_bft_is_leader(w)) {
            fprintf(stderr, "%s: P2 no PROPOSE within %u ms of the view "
                    "change completing (view %u) — initiating view change "
                    "to %u\n", LOG_TAG, w->bft_config.round_timeout_ms,
                    w->current_view, w->current_view + 1);
#ifdef O15H_DIAG_ENABLED
            /* O15O Faz 1 — SKIP THE EMIT on a faulted read: a diagnostic
             * record claiming height 1 on a long chain is worse than an
             * absent record, because the whole point of the trace is
             * attribution.
             *
             * INSIDE THE COMPILE GATE, and it has to be. O15H_DIAG does
             * not evaluate its arguments when the option is off
             * (nodus_witness_o15h_diag.h), so the height query costs a
             * production build nothing today; hoisting it out here would
             * add a DB round trip to a default build and break the
             * byte-identity property that header states is what makes the
             * instrumentation revertible. Same shape as the o15h_slot
             * carrier in nodus_witness_handlers.c. */
            {
                uint64_t p2_diag_tip = 0;
                if (nodus_witness_block_height_checked(w, &p2_diag_tip) != 0) {
                    fprintf(stderr, "%s: P2 deadman — chain-height read "
                            "faulted; diagnostic record skipped\n", LOG_TAG);
                } else {
                    O15H_DIAG(w, "p2_propose_deadman", w->my_id,
                              p2_diag_tip + 1, w->current_view,
                              w->current_view + 1, w->round_state.phase,
                              w->round_state.phase_start_time,
                              w->bft_config.round_timeout_ms, "-", 0,
                              (unsigned)w->mempool.count,
                              w->bft_config.quorum,
                              "post-view-change PROPOSE wait expired");
                }
            }
#endif
            /* Disarm BEFORE initiating: the deadline has been spent, and
             * leaving it set would re-fire on every subsequent tick. The
             * next completed view change arms the next window. */
            w->awaiting_propose_deadline_ms = 0;
            w->round_state.phase_start_time = time_ms();
            nodus_witness_bft_initiate_view_change(w);
            return;
        }

        /* ── O15I P3 — THE DEMAND-ARMED FOLLOWER DEADMAN, FIRE ─────────
         *
         * P2 above keeps priority: it is the sharper signal (a view
         * change COMPLETED and the new leader still said nothing), and
         * its fire returns, so the two can never both act on one tick.
         *
         * WHAT THIS ONE CATCHES THAT P2 CANNOT. P2 only ever arms in the
         * aftermath of a completed view change. The 20-node terminal
         * state had no view change at all: `leader = (epoch + view) % n`
         * with `epoch = height / DNAC_EPOCH_LENGTH` gives ONE node an
         * entire epoch (720 heights in production), only the leader
         * leaves IDLE on its own (nodus_witness.c, the mempool block
         * timer), and so with that leader dead every node sat IDLE at
         * view 0 and NOTHING ever asked for a rotation. Height 43 of
         * that run recorded zero consensus events of any kind.
         *
         * THE EVIDENCE IS LOCAL AND MESSAGE-FREE: our own committed tip
         * has not moved for longer than a round, while we hold work that
         * could still be included. Both halves are required —
         *   - without the DEMAND half a quiet, healthy chain (whose tip
         *     is legitimately frozen) would rotate the view forever;
         *   - without the FROZEN-TIP half a busy chain would rotate away
         *     from a leader that is producing perfectly well.
         *
         * ORDER OF THE TESTS IS DELIBERATE, cheapest first — this runs
         * ~20x/s per witness:
         *   1. the two counters, free, and they alone short-circuit
         *      every node on a quiet chain;
         *   2. one committed-tip read, the same query P1 makes above,
         *      and only for a node that HAS demand;
         *   3. the age comparison, free;
         *   4. the consensus-active gate (one field load, O15I V2 — see
         *      the P2 fire site above for why a zero bft_config makes
         *      step 3 true at every one-second boundary), then the
         *      staleness scan, then nodus_witness_bft_is_leader — a
         *      committee load plus a SHA3-512 per member, which is why
         *      that one is last.
         *
         * EVERY VERDICT AT THE WOULD-FIRE POINT RE-STAMPS THE WINDOW,
         * and that is load-bearing twice over. It bounds steps 4-5 to
         * once per round_timeout_ms rather than once per tick (a node
         * whose whole mempool is stale would otherwise re-scan the DB
         * 20x/s forever); and on the FIRE path it is the same discipline
         * P2 applies when it zeroes its spent deadline — without it, the
         * next return to IDLE with the tip still frozen would re-fire on
         * the very first tick, which is the O15H D2 churn shape entering
         * through a new door.
         *
         * THE PHASE-CLOCK RE-STAMP IS KEPT for P2's reason exactly.
         * Since O15M, initiate_view_change stamps phase_start_time
         * itself, beside the write that moves the phase to VIEW_CHANGE,
         * so the invariant holds for the ordinary path from here without
         * this line. It does NOT hold when initiate_view_change returns
         * at its early return — the dead-episode flags — and this stamp
         * is what bounds the escalation's budget in that state. The
         * adoption block in handle_viewchg stamps only when the phase is
         * ALREADY VIEW_CHANGE (:7610-7611), which it is not here: we are
         * entering from IDLE. Without a stamp on either side the
         * VIEW_CHANGE branch below would measure this view change's age
         * from a round that ended long ago and escalate the target on
         * the next tick, forever.
         *
         * SAFETY. `current_view` is NOT touched here. As of O15N Faz 2C2
         * it has exactly TWO write sites — bft_viewok_apply in this file,
         * on a verified VIEW_OK proof, and nodus_witness_db.c's restore
         * of this node's own previously proven value. The three unproven
         * message-driven writes this comment used to list (the PROPOSE
         * copy, the view-change quorum self-advance and the NEW_VIEW
         * accept) are gone, and the IDENT adoption was DELETED in
         * v0.19.24. P3 adds neither survivor. The
         * TARGET is the ordinary current_view + 1 that
         * initiate_view_change picks; this path invents no rule.
         *
         * LIVENESS COST — restated honestly (O15I V1). The original claim
         * here was "a quiet chain has no demand, so nothing ever arms".
         * THAT WAS FALSE, and it is the exact hole V1 closes: a follower
         * holding one settled successor class-200 envelope had a non-empty
         * mempool on a chain that was otherwise perfectly quiet, so the
         * window armed and bft_p3_live_demand answered live forever.
         *
         * What is true now: the window arms on a NON-EMPTY POOL, which a
         * quiet chain can still have; the rotation is then gated on
         * bft_p3_live_demand, which asks the chain whether any pooled
         * entry could still be included. A pool of FINISHED entries — a
         * spent nullifier, an already-committed intent, an expired
         * envelope, or bytes that no longer decode — is not demand and
         * produces no rotation, and the reaper deletes those copies on
         * the next epoch anyway. While GENUINE demand is stalled, ONE
         * rotation per round_timeout_ms is the intended behaviour, not a
         * side effect. */
        if (w->mempool.count > 0 || w->pending_forward_count > 0) {
            uint64_t p3_now = time_ms();

            /* ── O15O Faz 1 — A TIP THIS NODE COULD NOT READ IS NOT A
             * FROZEN TIP.
             *
             * P3's entire premise is an OBSERVATION: this node watched the
             * committed tip stand still for a full round while demand was
             * pending, and concluded the leader is not doing its job. A
             * failed read is not that observation — it is the absence of
             * one — and acting on it broadcasts a VIEW_CHANGE to the whole
             * cluster on the strength of a value that was never obtained.
             *
             * So the ENTIRE window is skipped: `tip_since_ms` is not
             * re-stamped, `last_seen_tip` is not touched, and the fire
             * gate is not evaluated. The window resumes on the next tick
             * that can actually read the tip, and it resumes from the
             * observation it genuinely last made.
             *
             * ⚠ THIS CONVERTS A PRE-EXISTING HAZARD; IT DOES NOT FIX ONE
             * O15O CREATED. The old accessor also answered 0 on a fault,
             * and nodus_witness_bft_is_leader already returned false
             * through its `lc_rc != 0` branch, so the reachable path was:
             * a sustained fault stores last_seen_tip = 0, the next tick
             * compares 0 to 0 and falls through to the `else if`, the
             * window elapses, and bft_p3_live_demand answers true off
             * pending_forward_count without touching the DB at all
             * (:10360-10361) — so the rotation fired against a tip nobody
             * read. That was true before this phase and is closed here.
             *
             * LOG VOLUME — a known deviation, recorded rather than hidden.
             * O15O asked for one line per window; a per-window limiter
             * needs per-witness state, and the two fields that could carry
             * it are the two this branch is required NOT to write, while
             * nodus_witness.h is outside this phase's file whitelist. So
             * this prints per tick while a fault persists AND demand is
             * pending — bounded by the demand test above, and the same
             * volume nodus_witness_bft_is_leader deliberately accepts for
             * this exact fault class at this exact tick rate (:868-874:
             * "a persistent fault prints on every tick. That is deliberate
             * and it is the requirement"). A dedicated stamp field would
             * close it in one line. */
            uint64_t p3_tip = 0;
            if (nodus_witness_block_height_checked(w, &p3_tip) != 0) {
                QGP_LOG_ERROR(LOG_TAG,
                    "P3 deadman: chain-height read faulted — skipping the "
                    "whole tip-frozen window (no re-stamp, no fire). A tip "
                    "this node could not read is not a frozen tip, and is "
                    "no grounds to rotate the view");
                return;
            }

            if (w->tip_since_ms == 0 || p3_tip != w->last_seen_tip) {
                /* First observation, or the chain MOVED — either way the
                 * leader is doing its job and the window starts now. */
                w->last_seen_tip = p3_tip;
                w->tip_since_ms = p3_now;
            } else if (p3_now - w->tip_since_ms >
                       w->bft_config.round_timeout_ms) {
                /* Re-stamp BEFORE deciding, so every verdict below —
                 * fire, all-stale, or leader — costs one evaluation per
                 * window and not one per tick. */
                w->tip_since_ms = p3_now;

                if (nodus_witness_bft_consensus_active(w) &&
                    bft_p3_live_demand(w) &&
                    !nodus_witness_bft_is_leader(w)) {
                    fprintf(stderr, "%s: P3 committed tip frozen at %llu for "
                            "more than %u ms with live demand (mempool=%d, "
                            "fwd=%d) — initiating view change to %u\n",
                            LOG_TAG, (unsigned long long)p3_tip,
                            w->bft_config.round_timeout_ms,
                            w->mempool.count, w->pending_forward_count,
                            w->current_view + 1);
                    O15H_DIAG(w, "p3_demand_deadman", w->my_id, p3_tip + 1,
                              w->current_view, w->current_view + 1,
                              w->round_state.phase,
                              w->round_state.phase_start_time,
                              w->bft_config.round_timeout_ms, "-", 0,
                              (unsigned)w->mempool.count, w->bft_config.quorum,
                              "committed tip frozen while demand is pending");
                    /* Disseminate BEFORE rotating, so the peers already
                     * hold the work when the rotation completes. */
                    bft_p3_broadcast_demand(w);
                    w->round_state.phase_start_time = time_ms();
                    nodus_witness_bft_initiate_view_change(w);
                    return;
                }
            }
        } else {
            /* No demand — the window is not running at all. Clearing it
             * rather than letting it age is what makes the arm honest:
             * demand arriving on a long-quiet chain then measures its
             * wait from the moment it arrived, and the leader gets a
             * full round to answer it before anyone rotates. */
            w->tip_since_ms = 0;
        }

        /* O15H TEMPORARY DIAGNOSTIC — the whole point of this return is
         * what is under investigation: an IDLE node arms no timeout, so
         * it can never initiate a view change. Record the fact once every
         * 10 s per witness (the tick runs ~20x/s) with the leadership
         * inputs, so "14 nodes sat IDLE at view 0 while the epoch leader
         * was dead" is an observation and not an inference. */
        if (O15H_DIAG_RATE(w, 1u, 10000u)) {
            /* O15O Faz 1 — skip the emit on a faulted read, for the same
             * reason and inside the same compile gate as the P2 record
             * above: a heartbeat claiming height 1 would misattribute the
             * very stall this record exists to explain. O15H_DIAG_RATE is
             * a literal 0 when the option is off, so this whole block is
             * already dead in a default build; the explicit #ifdef keeps
             * the height query out of it regardless of how the compiler
             * folds the constant. */
#ifdef O15H_DIAG_ENABLED
            uint64_t idle_diag_tip = 0;
            if (nodus_witness_block_height_checked(w, &idle_diag_tip) != 0) {
                fprintf(stderr, "%s: idle_stall — chain-height read "
                        "faulted; diagnostic record skipped\n", LOG_TAG);
            } else {
                O15H_DIAG(w, "idle_stall", w->my_id,
                          idle_diag_tip + 1, w->current_view,
                          w->view_change_target, w->round_state.phase,
                          w->round_state.phase_start_time,
                          time_ms() - w->round_state.phase_start_time, "-",
                          nodus_witness_bft_is_leader(w) ? 1 : 0,
                          (unsigned)w->mempool.count, w->bft_config.quorum,
                          "IDLE — no timeout armed, no view change possible");
            }
#endif
        }
        return;
    }

    uint64_t elapsed = time_ms() - w->round_state.phase_start_time;

    /* O15H D5 — a stalled view change ESCALATES; it does not give up.
     *
     * The old body here returned the node to IDLE with current_view
     * unchanged and the tally wiped, on the reasoning that this
     * "prevents the node from being permanently stuck". It does the
     * opposite. From IDLE this function returns at its first branch, so
     * the node never times out again; current_view did not move, so the
     * leader is still the same (possibly dead) node; and nothing else
     * re-initiates. The node sits idle until some peer's VIEW_CHANGE
     * happens to arrive — and every peer reached the same dead end.
     *
     * That was MASKED until now: D2 (the missing phase_start_time stamp
     * below) made this branch fire on the very first tick of every view
     * change, so the constant churn kept re-arming everyone. With the
     * clock fixed, reaching this point means a genuine 10 s failure to
     * assemble quorum — and the dead end becomes a real halt. Fixing D2
     * without fixing this would trade a fast stall for a slow one.
     *
     * The PBFT-standard behaviour is to retry the view change at the
     * NEXT view, and that is what this does. SAFETY IS UNCHANGED:
     * `current_view` is advanced in exactly one place in this file, on a
     * verified VIEW_OK proof (bft_viewok_apply — O15N Faz 2C2 moved it
     * there from bft_vc_check_quorum), and this path does not touch it.
     * Only the
     * TARGET moves, so leader election, the C5 binding and the NEW_VIEW
     * proof all keep their existing preconditions. Records for the
     * abandoned target are cleared for the same reason handle_viewchg
     * clears them when it adopts a higher target: a lower target's
     * prepared cert must never be counted in a higher target's scan.
     *
     * Convergence: nodes that escalate at slightly different moments
     * adopt each other's HIGHEST target through handle_viewchg, which
     * (D2, second half) also restarts the adopter's clock — so an
     * adopter always gets a full window at the target it converged on.
     * The interval is deliberately FIXED rather than backed off: a
     * per-node backoff is per-node timing state, and timing state that
     * differs between witnesses is what this file exists to avoid. */
    if (w->round_state.phase == NODUS_W_PHASE_VIEW_CHANGE) {
        if (elapsed > w->bft_config.viewchg_timeout_ms) {
            bool have_target = (w->view_change_in_progress &&
                                w->view_change_target > w->current_view);

            /* O15H D9 — plain escalation. The D5b "join the adopted
             * target instead of overshooting it" branch that used to
             * live here is GONE because D9 made its premise
             * unreachable: adoption now requires f+1 backers, and the
             * f+1 join rule fires on the same condition in the same
             * call, so a target can no longer be adopted while our own
             * vote is still missing from it. Keeping a branch whose
             * condition can never hold would be dead code guarding a
             * hazard that no longer exists — and the hazard it guarded
             * (running ahead of the cluster) is now handled properly, by
             * following the f+1-supported target in handle_viewchg. */
            uint32_t next_target = have_target ? w->view_change_target + 1
                                               : w->current_view + 1;

            fprintf(stderr, "%s: view change timeout (%lu ms) at %u/%u — "
                    "escalating target %u -> %u (current_view stays %u)\n",
                    LOG_TAG, (unsigned long)elapsed,
                    bft_vc_tally(w, w->view_change_target),
                    w->bft_config.quorum,
                    w->view_change_target, next_target, w->current_view);
            O15H_DIAG(w, "escalate", w->my_id, w->round_state.block_height,
                      w->current_view, next_target, w->round_state.phase,
                      w->round_state.phase_start_time, elapsed, "-", 0,
                      bft_vc_tally(w, w->view_change_target),
                      w->bft_config.quorum,
                      "view-change budget expired");

            /* O15H D9 — no clear on escalation either. Every record is
             * some voter's own current target; raising OUR target does
             * not retract theirs, and the per-target tally means records
             * at other targets cannot contaminate this one. Our own
             * record follows us, via the upsert in
             * bft_self_record_view_change. */
            w->view_change_in_progress = true;
            w->view_change_target = next_target;
            /* We have not voted for the NEW target yet — this is what
             * lets initiate_view_change past its D1 early-return. */
            w->view_change_voted = false;
            /* Fresh window for the new target (D2). */
            w->round_state.phase_start_time = time_ms();

            /* Re-broadcast + self-record at the escalated target. The
             * retained batch is deliberately NOT freed: a later view may
             * still have to re-propose it, and the tick-time guard in
             * nodus_witness.c releases it once the chain passes its
             * height. */
            nodus_witness_bft_initiate_view_change(w);
        }
        return;
    }

    if (elapsed > w->bft_config.round_timeout_ms) {
        /* MED-28 — RETAIN, do not free. A view change is starting; if it
         * completes with a prepared cert the new leader must be able to
         * re-propose these exact bytes, and no other copy survives. */
        nodus_witness_retained_batch_take(w);
        round_state_free_batch(&w->round_state);

        w->round_state.phase = NODUS_W_PHASE_VIEW_CHANGE;
        /* O15H D2 — RE-STAMP THE PHASE CLOCK. THIS ONE IS LOAD-BEARING,
         * and it is the reason O15M did not delete the hand-stamps.
         *
         * `elapsed` above is measured from phase_start_time, and that
         * field is only ever written at round entry (:4216 leader,
         * :5063 follower, :5916 on PREVOTE quorum). Entering
         * NODUS_W_PHASE_VIEW_CHANGE without re-stamping left the
         * VIEW_CHANGE branch of this function measuring the view
         * change's age from the ROUND's start — and since
         * viewchg_timeout_ms (10 s) is SHORTER than round_timeout_ms
         * (15 s, nodus_types.h:161-162), `elapsed > viewchg_timeout_ms`
         * was already true the moment the view change began. The next
         * tick (~150 ms) therefore aborted it and wiped
         * view_change_count.
         *
         * Signature in the 2026-08-25 rehearsal: "view change timeout
         * (16000 ms)" printing the SAME elapsed as the round timeout
         * that had just fired, at 8/14 votes — after which the tally
         * restarted at 1/14 and never converged. At N=7 the quorum of 5
         * usually landed inside that single tick, which is why this bug
         * only became fatal at N=20.
         *
         * (16000 not 15000 because time_ms() is nodus_time_now()*1000,
         * i.e. one-second granularity — :105-106.)
         *
         * O15M — WHY THIS LINE SURVIVES THE STAMP INSIDE
         * initiate_view_change. That stamp sits beside the phase write
         * and cannot be reached when the function returns at its early
         * return (:7226), which fires on `view_change_in_progress &&
         * view_change_voted`. Those two flags can BOTH be true here from
         * an episode that is already dead: the round-equality reset in
         * handle_commit (:6984-6987) puts the phase back to IDLE and
         * writes NEITHER of them, so a node that started a view change,
         * then took a remote COMMIT for the same round, then opened a
         * fresh round and timed out on it, arrives here still flagged.
         * The call below then returns immediately — no transition, no
         * self-record, no re-broadcast — and this line is the only thing
         * that gives the escalation above a window measured from NOW
         * rather than from the round that has just ended. Delete it and
         * D2 returns for exactly that state. */
        w->round_state.phase_start_time = time_ms();

        fprintf(stderr, "%s: round timeout (%lu ms), initiating view change\n",
                LOG_TAG, (unsigned long)elapsed);
        O15H_DIAG(w, "vc_enter_own_timeout", w->my_id,
                  w->round_state.block_height, w->current_view,
                  w->view_change_target, w->round_state.phase,
                  w->round_state.phase_start_time, elapsed, "-", 0,
                  bft_vc_tally(w, w->view_change_target),
                  w->bft_config.quorum,
                  "own round timeout — clock re-stamped here");
        nodus_witness_bft_initiate_view_change(w);
    }
}

/* ── Phase 6 commit wrappers ───────────────────────────────────────────
 *
 * These three wrappers compose apply_tx_to_state + finalize_block into
 * the named operations that the BFT round (Phase 7) and sync handler
 * (Phase 11) will call. Declared in nodus_witness_bft_internal.h for
 * test executables; not in any production header — Phase 7 / Phase 11
 * add the public wiring.
 */

/* S3 — locate the optional chain_def trailer inside a serialized
 * genesis TX. Extracted from commit_genesis (the walk is byte-identical
 * to the one that lived inline there) so the sync path can derive the
 * genesis cert quorum from the SAME bytes Rule P verifies. Pure wire
 * walk, no state. @return 0 (blob out, may be NULL when absent) / -1
 * on NULL args. */
int nodus_witness_extract_chain_def(const uint8_t *tx_data,
                                    uint32_t tx_len,
                                    const uint8_t **cd_blob_out,
                                    uint32_t *cd_blob_len_out) {
    if (!tx_data || !cd_blob_out || !cd_blob_len_out) return -1;
    *cd_blob_out = NULL;
    *cd_blob_len_out = 0;

    const uint8_t *p = tx_data;
    const uint8_t *end = tx_data + tx_len;
    if (tx_len >= DNAC_TX_HEADER_SIZE) {
        p += DNAC_TX_HEADER_SIZE;  /* v2 header: version + type + timestamp + tx_hash + committed_fee */
        if (p < end) {
            uint8_t ic = *p++; p += (size_t)ic * (64 + 8 + 64); /* inputs */
        }
        if (p < end) {
            uint8_t oc = *p++;
            for (int oi = 0; oi < oc && p < end; oi++) {
                p += 1 + 129 + 8 + 64 + 32; /* version+fp+amt+token+seed */
                if (p < end) { uint8_t ml = *p++; p += ml; } /* memo */
            }
        }
        if (p < end) {
            uint8_t wc = *p++; p += (size_t)wc * (32 + NODUS_SIG_BYTES + 8 + NODUS_PK_BYTES); /* witnesses */
        }
        if (p < end) {
            uint8_t sc = *p++; p += (size_t)sc * (NODUS_PK_BYTES + NODUS_SIG_BYTES); /* signers */
        }
        /* Now at has_chain_def flag byte */
        if (p < end) {
            uint8_t has_cd = *p++;
            if (has_cd && p + 4 <= end) {
                uint32_t cd_len = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
                                | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
                p += 4;
                if (p + cd_len <= end) {
                    *cd_blob_out = p;
                    *cd_blob_len_out = cd_len;
                }
            }
        }
    }
    return 0;
}

/* Task 6.1 — single-TX genesis commit with chain DB bootstrap. */
int nodus_witness_commit_genesis(nodus_witness_t *w,
                                   const uint8_t *tx_hash,
                                   const uint8_t *tx_data,
                                   uint32_t tx_len,
                                   uint64_t timestamp,
                                   const uint8_t *proposer_id) {
    if (!w || !tx_hash || !tx_data) return -1;

    /* Chain DB bootstrap — lifted from legacy nodus_witness_commit_block.
     * The fingerprint walk + chain_id derivation is factored into
     * nodus_witness_genesis_derive_chain_id (above) so the genesis sync leg can
     * re-derive against the same code; the too-short/parse diagnostics live in
     * that helper. */
    if (!w->db) {
        uint8_t derived_chain_id[32];
        if (nodus_witness_genesis_derive_chain_id(tx_data, tx_len, tx_hash,
                                                  derived_chain_id) != 0) {
            fprintf(stderr, "%s: commit_genesis: derive_chain_id failed\n", LOG_TAG);
            return -1;
        }
        if (nodus_witness_create_chain_db(w, derived_chain_id) != 0) {
            fprintf(stderr, "%s: commit_genesis: create_chain_db failed\n", LOG_TAG);
            return -1;
        }
    }

    /* Extract chain_def trailer from genesis TX (if anchored genesis).
     * Moved BEFORE apply_tx_to_state so Rule P.2 can reject ghost-stake
     * genesis TXs before any state mutation — see
     * dnac/docs/plans/2026-04-19-genesis-ghost-stake-fix.md.
     * S3: the walk itself moved into nodus_witness_extract_chain_def so
     * the sync path can reuse it for genesis cert-quorum derivation. */
    const uint8_t *cd_blob = NULL;
    uint32_t cd_blob_len = 0;
    uint64_t cd_supply = 0;
    uint8_t  cd_vcount = 0;
    if (nodus_witness_extract_chain_def(tx_data, tx_len,
                                        &cd_blob, &cd_blob_len) == 0 &&
        cd_blob) {
        QGP_LOG_INFO(LOG_TAG, "Genesis TX carries chain_def trailer (%u bytes)",
                     cd_blob_len);
    }

    /* Rule P.2 — outputs_sum + initial_validator_count * SELF_STAKE ==
     * initial_supply_raw. Prevents ghost-stake genesis where an operator
     * (or buggy client) creates a recipient UTXO equal to gross supply
     * without deducting validator self-stake locks. */
    if (cd_blob && cd_blob_len > 0) {
        if (nodus_witness_parse_cd_supply(cd_blob, (size_t)cd_blob_len,
                                           &cd_supply, &cd_vcount) != 0) {
            fprintf(stderr, "%s: Rule P.2 — chain_def parse failed\n", LOG_TAG);
            return -1;
        }
        if (cd_vcount > 0) {
            /* Parse outputs_sum (native DNAC only) from tx_data. */
            uint64_t outputs_sum = 0;
            if (tx_len > DNAC_TX_HEADER_SIZE) {
                size_t off = DNAC_TX_HEADER_SIZE;
                uint8_t in_count = tx_data[off++];
                off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);
                if (off < tx_len) {
                    uint8_t out_count = tx_data[off++];
                    for (int i = 0; i < out_count && off + 235 <= tx_len; i++) {
                        off += 1;    /* version */
                        off += 129;  /* fingerprint */
                        uint64_t amt;
                        memcpy(&amt, tx_data + off, 8);
                        off += 8;
                        const uint8_t *tid = tx_data + off;
                        off += 64;
                        off += 32;  /* nullifier_seed */
                        uint8_t ml = tx_data[off++];
                        off += ml;
                        /* Native DNAC only — token_id == all zeros. */
                        bool is_native = true;
                        for (int bi = 0; bi < 64; bi++) if (tid[bi] != 0) { is_native = false; break; }
                        if (is_native) outputs_sum += amt;
                    }
                }
            }
            uint64_t stake_locked = (uint64_t)cd_vcount * DNAC_SELF_STAKE_AMOUNT;
            if (stake_locked > cd_supply) {
                fprintf(stderr,
                    "%s: Rule P.2 — stake_lock=%llu > initial_supply_raw=%llu\n",
                    LOG_TAG,
                    (unsigned long long)stake_locked,
                    (unsigned long long)cd_supply);
                return -1;
            }
            uint64_t expected = cd_supply - stake_locked;
            if (outputs_sum != expected) {
                fprintf(stderr,
                    "%s: Rule P.2 REJECT — outputs_sum=%llu != expected=%llu "
                    "(initial_supply=%llu minus %u x self_stake=%llu). "
                    "Genesis TX would create ghost stake — rejecting.\n",
                    LOG_TAG,
                    (unsigned long long)outputs_sum,
                    (unsigned long long)expected,
                    (unsigned long long)cd_supply,
                    (unsigned)cd_vcount,
                    (unsigned long long)stake_locked);
                return -1;
            }
            QGP_LOG_INFO(LOG_TAG,
                "Rule P.2 OK — outputs_sum=%llu, stake_lock=%llu, total=%llu",
                (unsigned long long)outputs_sum,
                (unsigned long long)stake_locked,
                (unsigned long long)cd_supply);
        }
    }

    if (nodus_witness_db_begin(w) != 0) return -1;

    /* O15O Faz 1 — the height the genesis block is written AT, inside the
     * open transaction. A fault answering 0 would apply and finalize the
     * block at height 1 on a chain that is not empty. Roll back and
     * refuse, exactly as every other failure inside this transaction
     * does. */
    uint64_t gen_tip = 0;
    if (nodus_witness_block_height_checked(w, &gen_tip) != 0) {
        fprintf(stderr, "%s: commit_genesis — chain-height read faulted "
                "inside the transaction; rolling back\n", LOG_TAG);
        nodus_witness_db_rollback(w);
        return -1;
    }
    uint64_t bh = gen_tip + 1;
    if (apply_tx_to_state(w, tx_hash, NODUS_W_TX_GENESIS, NULL, 0,
                           tx_data, tx_len, bh, timestamp, NULL,
                           NULL, NULL) != 0) {
        nodus_witness_db_rollback(w);
        return -1;
    }

    /* v0.16 supply-invariant fix — write genesis_state + supply_tracking
     * with the full initial_supply_raw from chain_def (cd_supply), not
     * the outputs_sum. The supply invariant at finalize_block observes
     * utxo + self_stake + delegated + pool; self_stake for the 7 bootstrap
     * validators (7 × DNAC_SELF_STAKE_AMOUNT) is seeded next by
     * genesis_seed_validators. Using cd_supply keeps
     * expected = genesis_supply + minted − burned balanced against
     * observed for every block starting at h=1. */
    {
        int rc = nodus_witness_genesis_set(w, tx_hash, cd_supply, tx_hash);
        if (rc != 0 && rc != -2) {
            fprintf(stderr, "%s: genesis record failed: %d\n", LOG_TAG, rc);
            nodus_witness_db_rollback(w);
            return -1;
        }
        int src = nodus_witness_supply_init(w, cd_supply, tx_hash);
        if (src != 0 && src != -2) {
            fprintf(stderr, "%s: supply_init failed: %d\n", LOG_TAG, src);
            nodus_witness_db_rollback(w);
            return -1;
        }
    }

    /* Phase 12 Task 57 — seed validator_tree + reward_tree from the
     * initial_validators[] block of the chain_def. Runs inside the same
     * db transaction as apply_tx_to_state / finalize_block, so a failure
     * rolls back atomically with the genesis commit. */
    if (nodus_witness_genesis_seed_validators(w, cd_blob, (size_t)cd_blob_len) != 0) {
        fprintf(stderr, "%s: genesis_seed_validators failed\n", LOG_TAG);
        nodus_witness_db_rollback(w);
        return -1;
    }

    if (finalize_block(w, tx_hash, 1, proposer_id, timestamp, bh,
                       cd_blob, (size_t)cd_blob_len, NULL) != 0) {
        nodus_witness_db_rollback(w);
        return -1;
    }
    return nodus_witness_db_commit(w);
}

/* Task 6.2 — multi-TX batch commit with SAVEPOINT attribution replay. */
int nodus_witness_commit_batch(nodus_witness_t *w,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t expected_height,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id,
                                 const uint8_t *expected_state_root) {
    if (!w || !entries || count <= 0 || count > NODUS_W_MAX_BLOCK_TXS) return -1;

    nodus_witness_batch_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    /* F17 determinism fix historically snapshotted w->block_fee_pool
     * here so rollback paths could restore it on retried/attribution-
     * replay passes. v0.16 stage A.5 deletes the field outright — fees
     * no longer live in RAM state at all — so the snapshot becomes a
     * no-op. Stage F.1 re-enforces determinism through the hard supply
     * invariant at finalize_block. */

    if (nodus_witness_db_begin(w) != 0) return -1;

    /* 2026-05-02 audit M-1 — TOCTOU snapshot guard. handle_commit
     * pre-validated cmt->block_height == local_next; commit_batch
     * re-checks under the DB transaction so any race window between
     * the two reads (single-threaded epoll guarantees none today, but
     * defense in depth for future threading) is caught. Rollback +
     * return -1 instead of applying at the wrong height — that was
     * the live bug US-1 hit at h=114 on 2026-05-01. */
    /* O15O Faz 1 — this IS the TOCTOU guard, so a fault must take the
     * same exit the mismatch below takes. Answering 0 would make
     * local_next 1 and pass any batch claiming height 1 straight into
     * apply+finalize on a long chain: the exact h=114 shape M-1 exists
     * to stop. Roll back and refuse. */
    uint64_t cb_tip = 0;
    if (nodus_witness_block_height_checked(w, &cb_tip) != 0) {
        fprintf(stderr,
            "%s: commit_batch — chain-height read faulted inside the "
            "transaction; rolling back rather than applying at an "
            "unverified height\n", LOG_TAG);
        nodus_witness_db_rollback(w);
        return -1;
    }
    uint64_t local_next = cb_tip + 1;
    if (expected_height != local_next) {
        fprintf(stderr,
            "%s: commit_batch height mismatch "
            "(expected=%llu local_next=%llu) — rollback\n",
            LOG_TAG,
            (unsigned long long)expected_height,
            (unsigned long long)local_next);
        nodus_witness_db_rollback(w);
        return -1;
    }
    uint64_t bh = expected_height;

    /* Flat buffer of all TX hashes for finalize_block's tx_root compute */
    uint8_t tx_hashes[NODUS_W_MAX_BLOCK_TXS * NODUS_T3_TX_HASH_LEN];

    for (int i = 0; i < count; i++) {
        nodus_witness_mempool_entry_t *e = entries[i];
        if (!e) {
            nodus_witness_db_rollback(w);
            return -1;
        }

        const uint8_t *nul_ptrs[NODUS_T3_MAX_TX_INPUTS];
        for (int j = 0; j < e->nullifier_count; j++)
            nul_ptrs[j] = e->nullifiers[j];

        if (apply_tx_to_state(w, e->tx_hash, e->tx_type, nul_ptrs,
                               e->nullifier_count, e->tx_data, e->tx_len,
                               bh, timestamp, &ctx,
                               e->client_pubkey, e->client_sig) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "commit_batch: TX %d apply_tx failed", i);
            nodus_witness_db_rollback(w);
            return -1;
        }

        /* Append this TX's output future-nullifiers so subsequent TXs
         * in the batch see them via layer-3. Uses the same derivation
         * as propose_batch's layer-2 check. */
        extern int nodus_extract_output_nullifiers_public(const uint8_t *, uint32_t,
                                                            uint8_t [][64], int);
        /* Inline the same extraction logic because the propose_batch
         * helper is file-static. Rather than widen that helper's
         * visibility, re-derive here. */
        /* Parse tx_data outputs and compute nullifiers */
        if (e->tx_data && e->tx_len > DNAC_TX_HEADER_SIZE) {
            size_t off = DNAC_TX_HEADER_SIZE;
            uint8_t in_count = e->tx_data[off++];
            off += (size_t)in_count * (NODUS_T3_NULLIFIER_LEN + 8 + 64);
            if (off < e->tx_len) {
                uint8_t out_count = e->tx_data[off++];
                for (int oi = 0; oi < out_count && off + 235 <= e->tx_len &&
                                 ctx.seen_count <
                                 NODUS_W_MAX_BLOCK_TXS * NODUS_T3_MAX_TX_INPUTS;
                     oi++) {
                    off += 1;   /* version */
                    char fp_buf[129];
                    memcpy(fp_buf, e->tx_data + off, 128);
                    fp_buf[128] = '\0';
                    off += 129; /* fingerprint */
                    off += 8;   /* amount */
                    off += 64;  /* token_id */
                    const uint8_t *seed = e->tx_data + off;
                    off += 32;  /* seed */
                    if (off >= e->tx_len) break;
                    uint8_t ml = e->tx_data[off++];
                    off += ml;

                    /* SHA3-512(owner_fp || seed) — mirrors
                     * nodus_compute_output_nullifier in nodus_witness.c */
                    uint8_t nf_out[64];
                    uint8_t buf_in[192 + 32];
                    size_t fp_len = strlen(fp_buf);
                    if (fp_len > 192) fp_len = 192;
                    memcpy(buf_in, fp_buf, fp_len);
                    memcpy(buf_in + fp_len, seed, 32);
                    qgp_sha3_512(buf_in, fp_len + 32, nf_out);

                    memcpy(ctx.seen_nullifiers[ctx.seen_count++], nf_out, 64);
                }
            }
        }

        memcpy(tx_hashes + i * NODUS_T3_TX_HASH_LEN, e->tx_hash, NODUS_T3_TX_HASH_LEN);
    }

    /* C4 fix: credit proposer attendance INSIDE the outer txn BEFORE
     * finalize_block so the counter bump is part of THIS block's
     * validator_root → state_root. Moves what used to be a separate txn
     * in the leader/follower commit handlers into an atomic unit with
     * the block persist. If the UPDATE fails here, db_rollback below
     * reverts the whole block (safer than the old silent-divergence
     * behaviour). */
    if (nodus_witness_record_attendance(w, bh, proposer_id) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "commit_batch: record_attendance failed");
        nodus_witness_db_rollback(w);
        return -1;
    }

    if (finalize_block(w, tx_hashes, (uint32_t)count, proposer_id,
                        timestamp, bh, NULL, 0,
                        expected_state_root) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "commit_batch: finalize_block failed");
        nodus_witness_db_rollback(w);
        /* fall through to attribution replay */

        /* SAVEPOINT attribution replay — one TX at a time in a fresh
         * read-only transaction, check supply invariant after each,
         * roll back. The inner batch_ctx is empty so layer-3 does not
         * double-flag the chained check. */
        if (nodus_witness_db_begin(w) == 0) {
            for (int i = 0; i < count; i++) {
                if (nodus_witness_db_savepoint(w, "attr_sp") != 0) break;
                nodus_witness_batch_ctx_t empty_ctx;
                memset(&empty_ctx, 0, sizeof(empty_ctx));
                const uint8_t *nul_ptrs[NODUS_T3_MAX_TX_INPUTS];
                for (int j = 0; j < entries[i]->nullifier_count; j++)
                    nul_ptrs[j] = entries[i]->nullifiers[j];

                apply_tx_to_state(w, entries[i]->tx_hash, entries[i]->tx_type,
                                   nul_ptrs, entries[i]->nullifier_count,
                                   entries[i]->tx_data, entries[i]->tx_len,
                                   bh, timestamp, &empty_ctx,
                                   entries[i]->client_pubkey,
                                   entries[i]->client_sig);
                if (supply_invariant_violated(w)) {
                    QGP_LOG_ERROR(LOG_TAG,
                        "attribution: TX %d violates supply invariant", i);
                }
                nodus_witness_db_rollback_to_savepoint(w, "attr_sp");
            }
            nodus_witness_db_rollback(w);
        }
        return -1;
    }

    /* Phase 12 / Task 12.0 — populate per-entry committed coordinates
     * after the block lands. Used by the per-entry spend_result sender
     * (Task 12.5) so each receipt carries the height + tx_index. */
    for (int i = 0; i < count; i++) {
        if (entries[i]) {
            entries[i]->committed_block_height = bh;
            entries[i]->committed_tx_index = (uint32_t)i;
        }
    }

    int commit_rc = nodus_witness_db_commit(w);
    /* C5 — block committed, prepared cert is now redundant. Clearing
     * signals that a future VIEW_CHANGE initiated by this witness does
     * NOT need to protect this (view, height) pair. Kept intact on
     * db_commit failure so a retry path can still re-propose. */
    if (commit_rc == 0) {
        w->last_prepared.present = false;
        /* H-5: persist the cleared last_prepared so a post-commit
         * restart does not re-attach a stale prepared cert to a
         * future VIEW_CHANGE.
         *
         * O15O Faz 3 — loud, and never a halt. The WAL /
         * synchronous=NORMAL durability boundary that makes the loss
         * possible, and the owner's decision to log rather than halt, are
         * written out once in nodus_witness_bft_after_successor_commit;
         * this site only names the fact IT loses. Deliberately NOT a
         * rollback: the block above is already durably committed, and
         * undoing it over a lost bookkeeping row would be a far worse
         * failure than the stale certificate this warns about. */
        if (nodus_witness_db_save_pbft_state(w) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "commit_batch: the CLEARED prepared slot was NOT persisted "
                "after committing height %llu (stale cert height=%llu "
                "view=%u) — this node keeps consensus, but after a restart "
                "that stale prepared certificate may re-attach to a "
                "VIEW_CHANGE",
                (unsigned long long)bh,
                (unsigned long long)w->last_prepared.height,
                (unsigned)w->last_prepared.view);
        }

        /* O15I P2 — DISARM the propose-wait deadman. The legacy mirror
         * of the successor disarm in
         * nodus_witness_bft_after_successor_commit: same trigger (a
         * DURABLY committed block), same reasoning (the chain advanced,
         * so this node has no grounds to call the leader dead). Inside
         * the commit_rc == 0 block deliberately — a ROLLED-BACK commit
         * advanced nothing and must leave the timer running, or a
         * failing leader would silence the very rotation that recovers
         * from it. replay_block delegates here too (see the refresh
         * comment below), so this one line covers both follower paths on
         * the legacy lane. */
        w->awaiting_propose_deadline_ms = 0;

        /* PR 1 (2026-05-03): Refresh bft_config from on-chain committee
         * AFTER successful commit, mirroring the leader-side round-start
         * refresh at line 3346. Without this, follower nodes silently
         * drift from cluster committee on CHAIN_CONFIG TX changes
         * (red-team finding C-3, design doc
         * docs/plans/2026-05-03-witness-auto-bootstrap-design.md).
         * replay_block delegates to commit_batch (line 5967), so this
         * single insertion covers both follower paths.
         *
         * Pass block_height(w) + 1 to match leader semantics: refresh
         * loads the committee for the NEXT round. On failure latch
         * safety_halt and return -1 — same severity as leader path
         * (line 3346 returns -1 on refresh failure). Block is durably
         * committed at this point; the halt prevents further BFT
         * participation with potentially stale bft_config. */
        /* O15O Faz 1 — the height read is latched exactly as the refresh
         * failure below is, and for the same reason: the block is durably
         * committed, and a node that cannot establish the committee
         * governing its next height must not keep participating. A fault
         * answering 0 would silently refresh the quorum from the height-1
         * committee immediately after committing a block. */
        uint64_t pc_tip = 0;
        if (nodus_witness_block_height_checked(w, &pc_tip) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "commit_batch: post-commit chain-height read faulted — "
                "latching safety_halt rather than refreshing the quorum "
                "at height 1");
            w->safety_halt = true;
            return -1;
        }
        uint64_t next_bh = pc_tip + 1;
        if (refresh_bft_config_from_committee(w, next_bh) != 0) {
            QGP_LOG_ERROR(LOG_TAG,
                "commit_batch: post-commit bft_config refresh failed "
                "(next_bh=%llu) — latching safety_halt",
                (unsigned long long)next_bh);
            w->safety_halt = true;
            return -1;
        }

        /* O15J Faz 3 — the post-commit successor derivation (deriving a
         * V2 chain from a terminal legacy chain at the sealing epoch
         * boundary) is deleted with the activation ceremony. A pure-V2
         * chain is built once, from a config, by
         * nodus_witness_v2_gen_derive — never from a predecessor. */
    }
    return commit_rc;
}

/* Task 6.3 — replay a block from a sync_rsp. */
int nodus_witness_replay_block(nodus_witness_t *w,
                                 uint64_t rsp_height,
                                 nodus_witness_mempool_entry_t **entries,
                                 int count,
                                 uint64_t timestamp,
                                 const uint8_t *proposer_id,
                                 const uint8_t *expected_state_root) {
    if (!w || !entries || count <= 0 || count > NODUS_W_MAX_BLOCK_TXS) return -1;

    /* O15O Faz 1 — the ordering precondition for a synced block. A fault
     * answering 0 would accept a sync_rsp at height 1 and hand it to
     * commit_batch as an already-validated height. Refuse. */
    uint64_t local_height = 0;
    if (nodus_witness_block_height_checked(w, &local_height) != 0) {
        QGP_LOG_ERROR(LOG_TAG,
            "replay_block: chain-height read faulted — refusing the "
            "sync_rsp at h=%llu rather than replaying against an "
            "unknown local tip",
            (unsigned long long)rsp_height);
        return -1;
    }
    if (rsp_height != local_height + 1) {
        QGP_LOG_ERROR(LOG_TAG,
            "replay_block: out-of-order sync_rsp (h=%llu, local=%llu)",
            (unsigned long long)rsp_height,
            (unsigned long long)local_height);
        return -1;
    }

    /* O15J Faz 3 — the sync-side terminal refusal is deleted with the
     * activation ceremony; see the leader-side note in the propose path. */

    /* replay_block uses the same body as commit_batch — the only
     * difference is the height precondition above. Delegate to avoid
     * duplicating the apply+finalize+output-nullifier-append loop.
     * 2026-05-02: pass rsp_height as expected_height (already
     * validated == local + 1 by the precondition above). */
    return nodus_witness_commit_batch(w, entries, count, rsp_height, timestamp,
                                        proposer_id, expected_state_root);
}
