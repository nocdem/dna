/**
 * Nodus — O15O Faz 5 / O15P Faz 2 — THE REPLAY CACHE IS PER SENDER, ITS
 *                      ORDER IS NODE-LOCAL, AND ALL SIX RECORD SITES ARE
 *                      DRIVEN
 *
 * WHAT THIS PROVES.
 *   Two properties. The first is the O15O Faz 5 claim §1..§5 were written
 *   for, stated as the thing that would be FALSE if any of them failed:
 *
 *     A sender can consume, and can evict, only its OWN share of the
 *     replay-nonce cache; and a frame pays for a slot only once it has
 *     been AUTHORIZED.
 *
 *   The second is O15P Faz 2's, and it closes the gap the "WHAT IT CANNOT
 *   SEE" note below used to record:
 *
 *     EVERY ONE of the six nonce_record call sites really records — a
 *     well-formed frame delivered twice is refused the second time, at
 *     every handler that has a replay gate — and the per-sender slot
 *     table behaves sanely when more distinct senders arrive than it has
 *     slots.
 *
 *   Five of the six sites were placed by inspection below the same
 *   committee gate and were never driven; if one had been in the wrong
 *   place, nothing would have caught it. §6..§10 drive them, one section
 *   per handler, and §11 drives the 128-slot sender table past its
 *   capacity.
 *
 *   Two shipped defects made that false, and they are one mechanism seen
 *   from two sides (both in nodus/BUGS.md):
 *
 *   O15N-L1 — the table held 10000 entries GLOBALLY and, at capacity,
 *     freed an ENTIRE BUCKET selected by the smallest `timestamp`. That
 *     field came straight from `hdr->timestamp`, which the SENDER chooses
 *     and signs. One sender could therefore decide WHICH honest entries
 *     left the table, re-opening replay of captured frames. And all six
 *     T3 consumers inserted BEFORE their own chain_id and committee
 *     checks, so an unauthorised sender consumed the capacity that was
 *     supposed to protect authorised ones.
 *
 *   "the replay cache can be exhausted by HONEST traffic" — at the
 *     governance minimum block interval of 1 s (DNAC_CFG_MIN_BLOCK_
 *     INTERVAL_SEC, dnac/include/dnac/dnac.h:341) and ~4 broadcasts per
 *     node per round, one honest sender produces ~1200 nonces per 300 s
 *     TTL window. Against a global 10000 that overflows at 9 seats. The
 *     cache evicted under NORMAL operation, with no attacker at all —
 *     which is why the fix sizes the budget PER SENDER and derives the
 *     total from it, rather than dividing a fixed total by n.
 *
 *   The eleven sections below are named in EXECUTION order, and that
 *   order is load-bearing — see HOW IT CAN LIE.
 *
 *     §1  an ordinary repeat is still refused and a fresh nonce is still
 *         accepted                              (the anti-vacuity floor)
 *     §2  a frame the committee gate refuses consumes NO slot
 *                                             (record-after-the-gates)
 *     §3  "oldest" is the insert ORDER, not the wire timestamp
 *     §4  a flooder evicts ONLY ITSELF
 *     §5  THE ATTACK: a flood cannot evict an honest sender's nonce
 *     §6  the PROPOSE   record site records          (bft.c handle_propose)
 *     §7  the VOTE      record site records   (bft_handle_vote_inner)
 *     §8  the VIEWCHG   record site records          (handle_viewchg)
 *     §9  the VIEWOK    record site records          (handle_viewok)
 *     §10 the VIEWOK_REQ record site records         (handle_viewok_req)
 *     §11 the 128-slot SENDER TABLE, driven past capacity
 *
 *   §6..§10 all have the SAME three-leg shape, and the third leg is what
 *   makes the first two mean anything:
 *     (a) a well-formed frame is ADMITTED — it travels BELOW the record
 *         and reaches a refusal that NAMES ITSELF, or returns 0;
 *     (b) the IDENTICAL frame delivered again is REFUSED AS A REPLAY;
 *     (c) the same frame with a FRESH nonce is ADMITTED again — so (b)
 *         is a decision about the KEY and not a handler that refuses
 *         everything for an unrelated reason.
 *   The sixth site (handle_commit) is what §1..§5 already drive, so it
 *   gets no separate section.
 *
 * WHAT IT REQUIRES.
 *   Compile flags: NONE beyond a default nodus build. Registered through
 *   register_witness_test, which supplies NODUS_WITNESS_INTERNAL_API. No
 *   QGP_FAULT_INJECT, no O15H_DIAG, no NODUS_V2_* gate macro.
 *   DNAC_EPOCH_LENGTH is never assumed: every fixture chain stays at tip
 *   0 and every frame carries height 1, so all lookups land in epoch 0
 *   and the file behaves identically at the shipped 720 and at the
 *   harness's 15.
 *   Environment: NONE. No STAGEF_*, no NODUS_FAULT_*, no network, no node
 *   directories, no pre-exported variable. The one filesystem dependency
 *   is a writable /tmp for mkdtemp/mkstemp.
 *   Runtime: ~14 750 handler calls (§3 2047, §4 2048, §5 10500, §11 ~135,
 *   plus a handful). Each is one SQLite height read and one committee
 *   lookup served from the primed cache; measured expectation is low
 *   seconds. Keygen is the other cost: 10 identities for §1..§5, 8 for
 *   §6..§10 and 130 for §11 — 148 ML-DSA-87 keypairs.
 *   The one time-sensitive quantity is named under HOW IT CAN LIE.
 *
 * WHAT IT LEAVES BEHIND.
 *   On disk: nothing. Every section builds its chain database in its own
 *   mkdtemp() directory under /tmp and removes it with `rm -rf` before
 *   returning. The stderr-capture files are created with mkstemp and
 *   unlinked immediately, so they exist only as an open descriptor.
 *
 *   IN PROCESS: THE NONCE TABLE IS FILE-SCOPE STATIC IN libnodus AND IS
 *   NOT RESET BETWEEN SECTIONS. It cannot be — it is `static` inside
 *   nodus_witness_bft.c with no exported handle, and this phase's file
 *   whitelist contains no header to add one to. So this file leaves the
 *   table holding roughly 4 100 entries (§3's and §4's capped shares plus
 *   a handful) when it reaches §5, and ~6 100 when it reaches §6. That is
 *   DELIBERATE and is handled as follows, which is the answer to "which
 *   did you choose, a reset helper or a documented ordering":
 *
 *     DOCUMENTED ORDERING PLUS DISJOINT IDENTITIES.
 *     (a) Every section uses sender identities used by no other section.
 *         §1..§5 partition the `g_peers` array (§1→7, §2→8, §3→5,
 *         §4→3,4, §5→1,2). §6..§10 use a SEPARATE array, `g_ext`, and
 *         partition it too (§6→3, §7→4, §8→5, §9→6, §10→7; g_ext[0] is
 *         that fixture's own node and g_ext[1],[2] are committee filler
 *         that never sends). §11 uses a THIRD array allocated on the
 *         heap for the section's lifetime. Every identity in all three
 *         comes from its own qgp_dsa87_keypair call, so the arrays are
 *         disjoint by construction and not merely by index. The cache is
 *         keyed on (sender_id, nonce) and the budget is per sender, so
 *         one section's residue can neither be mistaken for another
 *         section's entry nor consume its capacity.
 *     (b) Every nonce is a DETERMINISTIC constant, not a random draw,
 *         which removes any birthday risk of a flood nonce colliding
 *         with a crafted one and making an eviction count come out
 *         wrong. The ranges are partitioned as well: §1..§5 hold
 *         0x101..0x502 with the floods at 0x4000…, §6..§10 hold
 *         0x601..0xA02, and §11 holds 0xB00+i (i < 128) plus 0xC01. It
 *         does NOT make the run byte-identical: the identities come from
 *         qgp_dsa87_keypair, so each sender_id — and therefore which
 *         BUCKET each entry lands in — differs every run. Nothing here
 *         depends on bucket placement; the only per-bucket operation is
 *         the TTL sweep, which frees expired entries only, and no entry
 *         in this file is expired while it is being asserted on.
 *     (c) The execution order §1..§5 is REQUIRED, but only for the
 *         REVERTED direction — see HOW IT CAN LIE. §6..§10 are free:
 *         each is self-contained on its own identities and asserts no
 *         eviction count. §11 MUST RUN LAST, and that is not a
 *         preference: it deliberately fills all 128 sender slots with
 *         its own identities, which EVICTS the entries every earlier
 *         section left behind. Anything scheduled after it would find an
 *         empty table.
 *
 * HOW IT CAN LIE.
 *   - THE OBSERVABLE FOR "REFUSED AS A REPLAY" IS INDIRECT, and this is
 *     the file's most important caveat. The replay check returns -1 and
 *     prints NOTHING, so it is identified by rc == -1 together with an
 *     EMPTY capture. What else could produce that pair?
 *     nodus_witness_bft_handle_commit's only earlier exits are the
 *     !w || !msg null guard (unreachable here) and the safety_halt
 *     refusal, WHICH PRINTS. Every guard below the replay check also
 *     prints. So on this fixture the pair is unambiguous — but it is
 *     weaker than a dedicated marker would be, and a future edit that
 *     added a silent early return above the check would fool it. It is
 *     named rather than papered over; no production log line was added
 *     for the test's benefit, because a line on the replay path is an
 *     attacker-triggerable log-amplification surface.
 *   - THE SAME ARGUMENT HAS TO BE MADE PER HANDLER IN §6..§10, AND IT IS
 *     NOT THE SAME ARGUMENT EVERY TIME. Each handler has its own set of
 *     exits above its replay check, and each section states which of them
 *     its fixture excludes:
 *       §6  PROPOSE  — above the check: safety_halt (PRINTS). Below it,
 *            the admitted leg is identified POSITIVELY by the A2 height
 *            gate's own line, so silence is only ever claimed for the
 *            replay leg.
 *       §7  VOTE     — above the check: safety_halt (silent, and the
 *            fixture never latches it). Below it and still silent:
 *            verify_chain_id's success, the msg-type filter, and the
 *            near-future vote BUFFER branch — which returns 0, not -1.
 *            The fixture supplies our own chain_id, a PREVOTE type and
 *            hdr->round == round_state.round, so none can fire; the
 *            admitted leg is identified by the C5 cert-verify line.
 *       §8  VIEWCHG, §9 VIEWOK, §10 VIEWOK_REQ — these three do NOT
 *            rest on silence at all. Every exit above their record site
 *            returns -1 and every path below it returns 0, so the RETURN
 *            CODE alone separates "recorded" from "refused as a replay".
 *            That is a stronger discriminator than §1..§7 have, and it is
 *            why those sections assert rc first and the empty window only
 *            as a corroborating leg.
 *   - "ADMITTED" MEANS "REACHED THE F02 BATCH RE-VERIFY", NEVER
 *     "COMMITTED A BLOCK". Every admitted leg still returns -1: past the
 *     committee gate the handler re-verifies each batch transaction in
 *     VALIDATION mode, which demands real Dilithium5-signed payloads. The
 *     same wall test_witness_commit_committee_gate.c and
 *     test_witness_height_fault_consumers.c §4 declined to climb, and the
 *     marker used here (L_BELOW) is the one those files use.
 *   - THE EXECUTION ORDER IS LOAD-BEARING FOR THE REVERT DIRECTION ONLY,
 *     AND THE ASYMMETRY IS THE ARGUMENT. Under the FIXED code no section
 *     can affect another: budgets are per sender and the identities are
 *     disjoint, so the order is free. Under a REVERTED build the single
 *     global 10000-entry cap is shared, and a section that ran after a
 *     big flood would find the table already at capacity — its own small
 *     flood would then trigger evictions for a reason that has nothing to
 *     do with what it is testing, and the victim would be whichever
 *     bucket happened to hold the smallest wire timestamp. That is
 *     exactly the non-determinism this project forbids. So the sections
 *     are ordered SMALL FLOODS FIRST and the one big flood LAST:
 *       * when §3 and §4 run, the reverted table holds ~5 and ~2 060
 *         entries, both far below 10000, so a reverted build performs NO
 *         eviction at all and their "it was evicted" assertions go red
 *         deterministically;
 *       * §5 runs last and its flood of 10500 exceeds the reverted cap
 *         even from an EMPTY table, so it reaches the eviction path no
 *         matter what preceded it; and its honest entry is stamped
 *         `now - 150`, the ONLY past-stamped entry in the entire file, so
 *         it is the unique global minimum by wire timestamp and the
 *         reverted rule frees ITS bucket first. Deterministic, not
 *         probabilistic.
 *   - THE FLOOD SIZES MIRROR A PRODUCTION CONSTANT. CAP_MIRROR below must
 *     equal NONCE_MAX_PER_SENDER in nodus_witness_bft.c. There is no way
 *     to include it (it is a #define in a .c file). A mismatch cannot
 *     pass quietly: too small a flood means no eviction and the
 *     "it was evicted" legs go red; too large means a second eviction and
 *     the "it survived" leg in §3 goes red.
 *   - §3 AND §4 DEPEND ON AN EXACT EVICTION COUNT. Each is sized so that
 *     EXACTLY ONE eviction fires. The arithmetic is written out at each
 *     site. If it is wrong the section fails loudly; it cannot pass
 *     vacuously, because both legs of each pair are asserted.
 *   - ONE TIME-SENSITIVE QUANTITY, NAMED. §5's honest entry is stamped
 *     `now - 150`, so it has 150 s of TTL life. §5's flood must finish
 *     and its assertion must run inside that window. At an expected
 *     ~150 µs per handler call the 10500-frame flood takes under two
 *     seconds; the margin is ~75x. If a machine were slow enough to
 *     exhaust it, the section fails — it does not silently pass. The
 *     stamp is not a tuned timeout: it is the minimum age that makes the
 *     entry the unique global timestamp minimum for the revert argument
 *     above, and it is the LARGEST such value this file uses.
 *   - FUTURE-STAMPED FLOODS WOULD MAKE §5 VACUOUS, AND THIS IS WHY THE
 *     FLOOD IS STAMPED AT `now`. The TTL comparison is
 *     `now - n->timestamp >= NONCE_TTL_SECS` on uint64 values
 *     (nodus_witness_bft.c, nonce_evict_bucket). For a timestamp in the
 *     FUTURE that subtraction underflows to ~2^64 and the entry is
 *     treated as ALREADY EXPIRED — so future-stamped entries are purged
 *     by the next sweep of their bucket and never accumulate. A flood of
 *     far-future frames therefore never fills a reverted table, no
 *     eviction ever fires, and the section would pass on the reverted
 *     build while proving nothing. Stamping the flood at `now` is what
 *     makes it a real flood. (O15N-L1's own write-up names far-future
 *     stamps as the mechanism; that half of the entry does not survive
 *     contact with the TTL line, while its CONCLUSION — the sender picks
 *     the victim — does, via a PAST stamp that ranks the sender's frame
 *     oldest.)
 *   - §11 IS ORDER-DEPENDENT WITHIN ITSELF, AND THE ORDER IS WRITTEN OUT
 *     AT THE SITE. Re-delivering an evicted sender's frame RE-RECORDS it,
 *     which claims a slot and therefore evicts the NEW least-recently-
 *     active sender. So the survivors must be asserted BEFORE the victim
 *     is re-delivered. The same trap §3 documents, one level up.
 *   - §11 DOES NOT DEPEND ON HOW MANY SLOTS §1..§10 LEFT OCCUPIED, and
 *     that independence is the whole reason it is constructed the way it
 *     is. `nonce_seq_next` is monotonic, so every entry §11 makes is
 *     NEWER than every entry any earlier section made; the eviction rule
 *     is least-recently-active by that same counter. Therefore 128
 *     distinct §11 senders, delivered in order into a 128-slot table,
 *     evict exactly the earlier sections' slots and leave the table
 *     holding EXACTLY those 128 — whatever number of them there were.
 *     The section asserts that state before it drives the 129th.
 *   - §11 ASSERTS WHAT THE CODE DOES, NOT WHAT WOULD BE NICE. On the
 *     129th distinct sender nonce_sender_claim drops the LEAST RECENTLY
 *     ACTIVE slot outright, freeing every entry that sender owned —
 *     re-opening self-replay for THAT ONE SENDER until it inserts again.
 *     The production comment says so in as many words and calls it an
 *     accepted, node-local residual. So the section asserts (a) nothing
 *     crashes, (b) the new sender IS recorded, (c) every OTHER sender's
 *     entry survives, and (d) the least-recently-active sender's entry is
 *     GONE. (d) is a characterisation of the shipped rule; if a future
 *     change made the table refuse the new sender instead, or drop a
 *     different one, this section goes red and that is the intended
 *     alarm.
 *   - WHAT IT CANNOT SEE. THE malloc-FAILURE BRANCH IN nonce_record IS
 *     DELIBERATELY UNEXERCISED. `nonce_record` ends with
 *     `nonce_node_t *node = malloc(...); if (node) { ...insert... }`, so
 *     on allocation failure the frame is simply not recorded. Proving
 *     that branch needs allocation failure ON DEMAND at one call site —
 *     an interposed allocator or a fault-injection hook — and neither
 *     exists in this tree; a global malloc interposer would also fire
 *     inside SQLite, Dilithium and the fixture itself, so the fixture
 *     could not be built at all. Building that machinery for one branch
 *     whose only effect is a missed record (fail-open on a cache, not on
 *     a gate) is out of proportion, and it is named here rather than
 *     quietly skipped.
 *     Also not exercised: a real T3 frame decode, a socket, a vote-buffer
 *     DRAIN (§7 delivers a LIVE vote; the drained-entry path deliberately
 *     carries no header and records nothing), and the TTL expiry sweep.
 *     handle_newview is NOT a seventh site and is not missing coverage:
 *     it has NEITHER a replay check NOR a nonce_record, deliberately —
 *     its own O15M block records that adding the bare is_replay line
 *     stalled the chain on the harness and was reverted, and grep
 *     confirms nonce_record has exactly six call sites, none in it.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_db.h"
#include "witness/nodus_witness_committee.h"
#include "protocol/nodus_tier3.h"
#include "transport/nodus_tcp.h"           /* nodus_time_now             */
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"

#include "dnac/dnac.h"        /* DNAC_EPOCH_LENGTH, DNAC_PROTOCOL_VERSION */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK FAIL %s:%d — %s\n", __FILE__, __LINE__, msg); \
        exit(1); \
    } \
    printf("  ok: %s\n", msg); \
} while (0)

/* ⚠ MUST EQUAL NONCE_MAX_PER_SENDER in nodus_witness_bft.c. It is a
 * #define inside a .c file, so it cannot be included; a divergence fails
 * this test loudly rather than quietly (see HOW IT CAN LIE). */
#define CAP_MIRROR   2048

/* §5's flood. Sized to exceed the 10000-entry GLOBAL cap this phase
 * deleted ON ITS OWN — before counting the ~4100 entries §1..§4 leave in
 * the shared table — so a reverted build reaches its eviction path no
 * matter what preceded it, and the claim does not rest on a residue
 * count that a later edit could change. */
#define FLOOD_BIG    10500

/* Ten seated peers; the committee primed over them is EIGHT, which
 * leaves peers 8 and 9 on the roster and outside it — the identity class
 * §2 needs. Peer 9 is never used and exists only so the roster is
 * strictly larger than the widened committee of §2. */
#define N_ROSTER          10
#define N_COMMITTEE        8
#define N_COMMITTEE_WIDE   9   /* §2's second leg — now includes peer 8 */
#define N_KEYS            10

/* Identity partition — no index appears in two sections. */
#define P_FLOOD_BIG     1   /* §5 flooder                                */
#define P_HONEST_BIG    2   /* §5 victim                                 */
#define P_FLOOD_SELF    3   /* §4 flooder                                */
#define P_HONEST_SELF   4   /* §4 bystander                              */
#define P_ORDER         5   /* §3                                        */
#define P_VACUITY       7   /* §1                                        */
#define P_OUTSIDER      8   /* §2 — roster, outside the BASE committee   */

/* Nonce space. Deterministic on purpose: a re-run feeds byte-identical
 * inputs, and no flood nonce can collide with a crafted one. Floods take
 * the high range; crafted nonces are small and distinct. */
#define N_VAC_A      0x0000000000000101ULL
#define N_VAC_B      0x0000000000000102ULL
#define N_GATE       0x0000000000000201ULL
#define N_ORDER_A    0x0000000000000301ULL
#define N_ORDER_B    0x0000000000000302ULL
#define N_SELF_FIRST 0x0000000000000401ULL
#define N_SELF_HON   0x0000000000000402ULL
#define N_BIG_HON    0x0000000000000501ULL
#define N_BIG_FRESH  0x0000000000000502ULL
#define N_FLOOD_BASE 0x4000000000000000ULL

/* ── O15P Faz 2 — §6..§11 ──────────────────────────────────────────
 *
 * A SEPARATE identity array so §1..§5 keep the exact roster, committee
 * and bft_config they were written against: widening `g_peers` would
 * change w->roster.n_witnesses, which feeds
 * nodus_witness_bft_config_init in the fixture, which changes the quorum
 * those sections run under. Nothing in §1..§5 asserts on the quorum
 * today, but the sections below handle_commit's record site do read it,
 * and a shared array would silently couple the two halves of this file.
 *
 * EIGHT is the committee §6..§10 prime: large enough that a leader index
 * can land on a peer that is neither this node nor a peer any other
 * section uses. */
#define N_EXT           8

/* Identity partition for the ext array — no index appears in two
 * sections. Index 0 is that fixture's OWN node; 1 and 2 are committee
 * filler that never sends anything. */
#define P_EXT_PROPOSE   3   /* §6  — and the leader for §6's view       */
#define P_EXT_VOTE      4   /* §7                                       */
#define P_EXT_VIEWCHG   5   /* §8                                       */
#define P_EXT_VIEWOK    6   /* §9                                       */
#define P_EXT_VOKQ      7   /* §10                                      */

#define N_PROP_A     0x0000000000000601ULL
#define N_PROP_B     0x0000000000000602ULL
#define N_VOTE_A     0x0000000000000701ULL
#define N_VOTE_B     0x0000000000000702ULL
#define N_VCHG_A     0x0000000000000801ULL
#define N_VCHG_B     0x0000000000000802ULL
#define N_VOK_A      0x0000000000000901ULL
#define N_VOK_B      0x0000000000000902ULL
#define N_VOKQ_A     0x0000000000000A01ULL
#define N_VOKQ_B     0x0000000000000A02ULL

/* §11 — the sender table. NONCE_MAX_SENDERS is NODUS_T3_MAX_WITNESSES
 * (128) in nodus_witness_bft.c, and that is also the capacity of
 * nodus_witness_roster_t::witnesses and of the committee cache — so ONE
 * fixture can authorise at most 128 distinct senders and the 129th needs
 * a second roster/committee configuration. That is why the section
 * re-seats the roster mid-way rather than simply delivering 129 frames.
 *
 * SLOTS_MIRROR must equal NONCE_MAX_SENDERS. Like CAP_MIRROR it cannot be
 * included (a #define inside a .c file) and a divergence cannot pass
 * quietly: too small and the 129th sender finds a free slot, so the
 * "the victim was dropped" leg goes red; too large and the fill loop
 * exceeds the roster capacity and the fixture refuses to build. */
#define SLOTS_MIRROR    128
#define N_OV            (SLOTS_MIRROR + 2)  /* 128 fillers + extra + self */
#define P_OV_EXTRA      SLOTS_MIRROR        /* the 129th distinct sender  */
#define P_OV_SELF       (SLOTS_MIRROR + 1)  /* this node; never a sender  */
#define N_OV_BASE    0x0000000000000B00ULL  /* + i, i < SLOTS_MIRROR      */
#define N_OV_EXTRA   0x0000000000000C01ULL

/* ═══════════════════════════════════════════════════════════════════
 * Fixture — the shape of test_witness_commit_committee_gate.c, this
 * season's own model.
 * ═══════════════════════════════════════════════════════════════════ */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} peer_t;

/* ML-DSA-87 keygen is the expensive part of the setup, so the identities
 * are generated ONCE in main and reused. Nothing in a section mutates
 * them. */
static peer_t g_peers[N_KEYS];

/* O15P Faz 2 — the §6..§10 identities. Disjoint from g_peers by
 * construction: every entry comes from its own qgp_dsa87_keypair call.
 * §11 allocates a THIRD array on the heap, for the same reason and with
 * the same disjointness. */
static peer_t g_ext[N_EXT];

static void peer_make(peer_t *p) {
    if (qgp_dsa87_keypair(p->pk, p->sk) != 0) {
        fprintf(stderr, "keygen failed\n"); exit(1);
    }
    /* The production voter-id derivation: SHA3-512(pubkey)[0..31]
     * (nodus_identity.c:42). */
    uint8_t d[64];
    if (qgp_sha3_512(p->pk, NODUS_PK_BYTES, d) != 0) {
        fprintf(stderr, "witness id derive failed\n"); exit(1);
    }
    memcpy(p->id, d, NODUS_T3_WITNESS_ID_LEN);
}

static void roster_put(nodus_witness_t *w, const peer_t *p) {
    uint32_t i = w->roster.n_witnesses++;
    memcpy(w->roster.witnesses[i].witness_id, p->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->roster.witnesses[i].pubkey, p->pk, NODUS_PK_BYTES);
    w->roster.witnesses[i].active = true;
}

/* Seat `n` peers on the roster in ARRAY ORDER, so a peer's array index and
 * its roster index are the same number. §1..§10 rely on that; §11 relies
 * on it twice, because it re-seats the roster from a different slice of
 * its array mid-section.
 *
 * ⚠ n_witnesses IS RESET, not appended to: this is also the re-seat path.
 * roster_put writes at w->roster.n_witnesses++, so zeroing the counter
 * overwrites the previous seating in place. */
static void roster_seat(nodus_witness_t *w, const peer_t *peers, int n) {
    w->roster.n_witnesses = 0;
    for (int i = 0; i < n; i++) roster_put(w, &peers[i]);
}

/* `self` is always this node, and the roster is seated in array order so
 * the peer array and w->roster.witnesses share indices.
 *
 * `self` is passed SEPARATELY from the roster slice on purpose: §11's
 * fixture keeps this node OFF the roster, because a roster of exactly
 * NODUS_T3_MAX_WITNESSES sender identities leaves no seat for it. Nothing
 * on the path §11 drives reads w->my_id — handle_commit's gates read the
 * SENDER only, and the frame is refused at the F02 batch re-verify well
 * above anything that would.
 *
 * nodus_witness_t is multi-MB: heap, never stack (repo discipline).
 * w->v2_successor is NEVER touched — the masking that
 * nodus_witness.c:736-738 records a previous test committing. */
static nodus_witness_t *fixture_from(char *dir_template, uint8_t tag,
                                     const peer_t *self,
                                     const peer_t *peers, int n_roster) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!w || !srv) { fprintf(stderr, "fixture alloc\n"); exit(1); }

    memcpy(srv->identity.pk.bytes, self->pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, self->sk,
           sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, self->id, NODUS_T3_WITNESS_ID_LEN);

    roster_seat(w, peers, n_roster);

    /* `tag` becomes the 16-byte chain_id (zero-filled to 32 by
     * set_chain_id), so it is NONZERO and verify_chain_id's "we hold an
     * identity, we enforce it" row applies — which is what lets every
     * crafted message carry w->chain_id and reach the committee gate. */
    if (mkdtemp(dir_template) == NULL) {
        fprintf(stderr, "mkdtemp failed\n"); exit(1);
    }
    snprintf(w->data_path, sizeof(w->data_path), "%s", dir_template);
    uint8_t chain_id[16];
    memset(chain_id, tag, sizeof(chain_id));
    if (nodus_witness_create_chain_db(w, chain_id) != 0 || !w->db) {
        fprintf(stderr, "create_chain_db failed\n"); exit(1);
    }

    /* THE CACHE SENTINEL, load-bearing: a calloc'd witness has
     * cached_committee_epoch_start == 0 and every query here is in epoch
     * 0, so left at the zero the resolver would take its cache-HIT branch
     * and answer (rc 0, count 0) without reading the database. Production
     * sets UINT64_MAX at init for the same reason. Set AFTER
     * create_chain_db so nothing it does can undo it. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;

    /* Nothing above the record reads the quorum, but the F02 batch
     * re-verify below it runs against a real config; initialise it
     * through the PRODUCTION initialiser rather than by hand. */
    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);
    return w;
}

/** §1..§5's fixture, unchanged: this node is g_peers[0] and the roster is
 *  the whole g_peers array. */
static nodus_witness_t *fixture(char *dir_template, uint8_t tag) {
    return fixture_from(dir_template, tag, &g_peers[0], g_peers, N_ROSTER);
}

static void fixture_free(nodus_witness_t *w, const char *dir) {
    if (w) {
        /* handle_commit appends no view-change record; defensive, and the
         * only correct reset if a future section ever drives one. */
        for (int i = 0; i < DNAC_MAX_ACTIVE_VALIDATORS; i++)
            nodus_witness_vc_record_clear(&w->view_changes[i]);
        nodus_witness_close(w);
        free(w->server);
        free(w);
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) { /* best-effort cleanup */ }
}

/* Prime the committee resolver's per-epoch cache with `peers[0..n)` for
 * the epoch CONTAINING `height`. nodus_committee_get_for_block answers
 * from this cache before it touches the database, and
 * load_committee_at_height_alloc goes through that accessor — so this
 * makes the governing committee a deterministic, DB-free input.
 *
 * Seating order is preserved, so a peer's array index is also its
 * COMMITTEE index — which is what lets §6 compare the production leader
 * index against a named identity.
 *
 * Parametric in DNAC_EPOCH_LENGTH: the epoch start is COMPUTED, never
 * assumed. Copied from prime_committee in
 * test_witness_commit_committee_gate.c. */
static void prime_committee_from(nodus_witness_t *w, uint64_t height,
                                 const peer_t *peers, int n) {
    uint64_t e = (uint64_t)DNAC_EPOCH_LENGTH;
    w->cached_committee_epoch_start = (height / e) * e;
    w->cached_committee_count = n;
    for (int i = 0; i < n; i++) {
        memcpy(w->cached_committee_pubkeys[i], peers[i].pk,
               DNAC_PUBKEY_SIZE);
        w->cached_committee_stakes[i]         = 1000000ULL + (uint64_t)i;
        w->cached_committee_self_stakes[i]    = 1000000000000000ULL;
        w->cached_committee_commission_bps[i] = 100;
    }
}

/** §1..§5's form, unchanged: the committee is always drawn from g_peers. */
static void prime_committee(nodus_witness_t *w, uint64_t height, int n) {
    prime_committee_from(w, height, g_peers, n);
}

/** Ask the loader directly what the gate is about to be told. */
static int committee_probe(nodus_witness_t *w, uint64_t height,
                             int *count_out) {
    nodus_committee_member_t *tmp =
        calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*tmp));
    if (!tmp) { fprintf(stderr, "probe alloc\n"); exit(1); }
    int rc = nodus_committee_get_for_block(w, height, tmp,
                                             DNAC_MAX_ACTIVE_VALIDATORS,
                                             count_out);
    free(tmp);
    return rc;
}

/* ═══════════════════════════════════════════════════════════════════
 * stderr capture — the discriminator that gives per-guard resolution.
 *
 * Every refusal on this path returns -1, so the return code alone cannot
 * say WHICH guard fired; the refusal line can, and its ABSENCE is what
 * identifies the silent replay check. In a nodus build QGP_LOG_* resolves
 * to nodus/src/nodus_log_shim.c, whose qgp_log_ring_add writes straight
 * to stderr, and the guards use bare fprintf(stderr, ...) anyway.
 *
 * The window wraps ONLY the call under test and stderr is restored BEFORE
 * anything is asserted: a CHECK that failed inside the window would write
 * its diagnosis into the temp file and the binary would exit 1 saying
 * nothing. Copied from test_witness_commit_committee_gate.c.
 * ═══════════════════════════════════════════════════════════════════ */

static int g_cap_fd = -1;
static int g_cap_saved = -1;

static void cap_begin(void) {
    char tmpl[] = "/tmp/nodus_rpc_XXXXXX";
    g_cap_fd = mkstemp(tmpl);
    if (g_cap_fd < 0) { fprintf(stderr, "mkstemp failed\n"); exit(1); }
    if (unlink(tmpl) != 0) {          /* leaves nothing behind */
        fprintf(stderr, "unlink failed\n"); exit(1);
    }
    fflush(stderr);
    g_cap_saved = dup(2);
    if (g_cap_saved < 0) { fprintf(stderr, "dup(2) failed\n"); exit(1); }
    if (dup2(g_cap_fd, 2) < 0) { fprintf(stderr, "dup2 failed\n"); exit(1); }
}

#define CAP_BUF 65536

/* Restore fd 2 and copy the window's output into `dst`.
 *
 * ⚠ THE DESTINATION IS CALLER-OWNED ON PURPOSE. Several sections hold one
 * leg's text while capturing the next; a shared static buffer would
 * silently overwrite the first. */
static void cap_end(char *dst, size_t cap) {
    fflush(stderr);
    if (g_cap_saved >= 0) {
        if (dup2(g_cap_saved, 2) < 0) _exit(1);
        close(g_cap_saved);
        g_cap_saved = -1;
    }
    dst[0] = '\0';
    if (g_cap_fd >= 0) {
        if (lseek(g_cap_fd, 0, SEEK_SET) == 0) {
            ssize_t n = read(g_cap_fd, dst, cap - 1);
            if (n < 0) n = 0;
            dst[n] = '\0';
        }
        close(g_cap_fd);
        g_cap_fd = -1;
    }
}

static bool said(const char *hay, const char *needle) {
    return strstr(hay, needle) != NULL;
}

/** THE REPLAY OBSERVABLE. The check prints nothing, so a refusal by it is
 *  rc == -1 with a completely empty window. See HOW IT CAN LIE. */
static bool silent(const char *hay) { return hay[0] == '\0'; }

/* ── The lines the assertions key on. ASCII only: the production messages
 *    carry em-dashes, which must never appear in a needle. ───────────── */
#define L_NONMEMBER "COMMIT from non-committee sender"
#define L_UNKNOWN   "COMMIT from unknown sender_id"
#define L_LOADFAULT "CANNOT ESTABLISH THE COMMITTEE at height"
/* The marker for "the frame travelled BELOW the committee gate and below
 * the nonce_record that follows it". Emitted by the F02 batch re-verify,
 * reachable only by passing every guard above it — the same marker
 * test_witness_commit_committee_gate.c and
 * test_witness_height_fault_consumers.c use for the same purpose. */
#define L_BELOW     "commit-path verify rejected batch TX"

/* ── O15P Faz 2 — the per-handler "we travelled below the record" markers.
 *
 * Each is a line printed by a guard that sits BELOW that handler's
 * nonce_record and is unique to it, so an ADMITTED leg is identified
 * POSITIVELY rather than by the absence of something. ASCII only: the
 * production lines carry em-dashes, which must never appear in a needle.
 * ────────────────────────────────────────────────────────────────── */

/* handle_propose's A2 height gate. "(proposal=" disambiguates it from
 * commit_batch's "commit_batch height mismatch (expected=" and
 * handle_commit's "height mismatch (commit=". */
#define L_PROP_BELOW  "height mismatch (proposal="
/* bft_handle_vote_inner's C5 PREVOTE certificate check. */
#define L_VOTE_BELOW  "PREVOTE cert_sig verify FAILED"
/* handle_viewok_req's success line, printed after the answer is sent. */
#define L_VOKQ_BELOW  "answered roster"

/* ── Guards ABOVE each new section's record site. Every section asserts
 *    these are ABSENT on its admitted leg, so "it reached the record" is
 *    not being inferred from a refusal that happened earlier. ───────── */
#define L_PROP_NOLEAD "proposal from non-leader"
#define L_PROP_NOSEND "proposal from unknown sender_id"
#define L_PROP_INROUND "round in progress"
#define L_PROP_VIEW   "but we hold view"
#define L_VOTE_NOSEND "vote from unknown sender"
#define L_VOTE_NOMEM  "vote from non-committee member"
#define L_VOTE_COMM   "cannot establish the committee at height"
#define L_VOTE_HASH   "vote for different tx_hash"
#define L_VCHG_NOMEM  "VIEW_CHANGE from non-committee sender"
/* The committee-load fault line is worded identically in five handlers
 * (only the verb prefix, which carries an em-dash, differs), so the
 * ASCII-only needle is the SHARED one — L_LOADFAULT above. Each new
 * section drives exactly one handler, so an occurrence of it inside that
 * section's window can only be that handler's. */
#define L_VOK_NOMEM   "VIEW_OK from non-committee sender"
#define L_VOK_NOCOMM  "no committee at height"
#define L_CHAINID     "chain_id mismatch"

/* ═══════════════════════════════════════════════════════════════════
 * Message builder
 * ═══════════════════════════════════════════════════════════════════ */

/* A transaction well-formed enough to REACH the F02 verify and be
 * rejected there BY NAME. The version byte is deliberately one past the
 * accepted one, so the reject is the cheap wire-version gate rather than
 * a NULL-pointer path — deterministic, and it depends on no signature
 * material. Taken from test_witness_commit_committee_gate.c. */
static uint8_t g_bogus_tx[8];

/* One COMMIT frame from `from` at height `bh`, carrying an EXPLICIT nonce
 * and an EXPLICIT wire timestamp. Both are explicit because this file is
 * about exactly those two fields: the nonce is the cache key and the
 * timestamp is the field the shipped eviction rule let the sender
 * choose. */
static void build_commit(nodus_t3_msg_t *m, const nodus_witness_t *w,
                         const peer_t *from, uint64_t bh,
                         uint64_t nonce, uint64_t ts) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_COMMIT;
    m->header.round = 1;          /* > last_committed_round (0)            */
    m->header.view = 0;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = ts;
    m->header.nonce = nonce;

    m->commit.block_height = bh;
    m->commit.batch_count = 1;
    m->commit.n_precommits = 0;   /* below the bh>=2 cert-quorum gate      */
    m->commit.proposal_timestamp = ts;
    memcpy(m->commit.proposer_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memset(m->commit.tx_root, 0xC5, NODUS_T3_TX_HASH_LEN);
    memset(m->commit.batch_txs[0].tx_hash, 0xC4, NODUS_T3_TX_HASH_LEN);
    m->commit.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
    m->commit.batch_txs[0].tx_data = g_bogus_tx;
    m->commit.batch_txs[0].tx_len = (uint32_t)sizeof(g_bogus_tx);
}

/** Deliver one COMMIT and capture the window. */
static int deliver(nodus_witness_t *w, const peer_t *from, uint64_t nonce,
                   uint64_t ts, char *out, size_t cap) {
    nodus_t3_msg_t m;
    build_commit(&m, w, from, /*bh*/ 1, nonce, ts);
    cap_begin();
    int rc = nodus_witness_bft_handle_commit(w, &m);
    cap_end(out, cap);
    return rc;
}

/** `n` admitted COMMITs from one sender, all at the SAME wire timestamp,
 *  each with a fresh deterministic nonce.
 *
 *  The message is built ONCE and only its nonce moves: nodus_t3_msg_t is
 *  a large union and re-memsetting it 10500 times would dominate the
 *  section's runtime for no benefit. handle_commit takes it by const
 *  pointer and never writes through it.
 *
 *  The whole flood runs inside ONE capture window and the text is thrown
 *  away — otherwise the ctest log would carry ~14600 handler diagnostics.
 *  A window is not a nested one: cap_begin/cap_end are strictly paired
 *  here and around every deliver(). */
static void flood(nodus_witness_t *w, const peer_t *from, uint64_t ts,
                  uint64_t nonce_base, int n) {
    static char scratch[4096];
    nodus_t3_msg_t m;
    build_commit(&m, w, from, /*bh*/ 1, nonce_base, ts);
    cap_begin();
    for (int i = 0; i < n; i++) {
        m.header.nonce = nonce_base + (uint64_t)i;
        (void)nodus_witness_bft_handle_commit(w, &m);
    }
    cap_end(scratch, sizeof(scratch));
}

/* ── O15P Faz 2 — one builder per handler §6..§10 drives.
 *
 * All five follow build_commit's shape: the header is written FIELD BY
 * FIELD with an EXPLICIT nonce and an EXPLICIT wire timestamp, because
 * those two fields are what this file is about, and a section re-delivers
 * the SAME struct to make the replay leg byte-identical.
 * ────────────────────────────────────────────────────────────────── */

/** One PROPOSE from `from` at `view`, claiming block height `bh`. */
static void build_propose(nodus_t3_msg_t *m, const nodus_witness_t *w,
                          const peer_t *from, uint32_t view, uint64_t bh,
                          uint64_t nonce, uint64_t ts) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_PROPOSE;
    m->header.round = 1;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = ts;
    m->header.nonce = nonce;

    m->propose.batch_count = 1;
    m->propose.block_height = bh;
    memset(m->propose.tx_root, 0xB6, NODUS_T3_TX_HASH_LEN);
    memset(m->propose.batch_txs[0].tx_hash, 0xB7, NODUS_T3_TX_HASH_LEN);
    m->propose.batch_txs[0].tx_type = NODUS_W_TX_SPEND;
}

/** One APPROVE PREVOTE from `from` for the live round's `target`.
 *
 *  cert_sig is left ALL ZERO: the C5 check below the record verifies it
 *  against the PREPARED preimage and refuses BY NAME, which is exactly
 *  the marker §7 keys on. A valid signature would carry the vote into the
 *  tally, where the pubkey dedup above the record would then swallow the
 *  fresh-nonce leg. */
static void build_prevote(nodus_t3_msg_t *m, const nodus_witness_t *w,
                          const peer_t *from, const uint8_t *target,
                          uint64_t nonce, uint64_t ts) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_PREVOTE;
    m->header.round = w->round_state.round;
    m->header.view = w->round_state.view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = ts;
    m->header.nonce = nonce;

    m->vote.vote = NODUS_W_VOTE_APPROVE;
    memcpy(m->vote.vote_target, target, NODUS_T3_TX_HASH_LEN);
}

/** One VIEW_CHANGE from `from` naming `new_view`. */
static void build_viewchg(nodus_t3_msg_t *m, const nodus_witness_t *w,
                          const peer_t *from, uint32_t new_view,
                          uint64_t nonce, uint64_t ts) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_VIEWCHG;
    m->header.round = 1;
    m->header.view = 0;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = ts;
    m->header.nonce = nonce;

    m->viewchg.new_view = new_view;
    m->viewchg.last_committed_round = 0;
    m->viewchg.has_prepared = false;
}

/** One VIEW_OK bundle from `from` — the ordinary broadcast shape, a
 *  single statement about (`height`, `view`). The signature bytes are
 *  never verified on the path §9 drives (that needs n_entries >= 2 AND a
 *  view ahead of ours), so they are a constant. */
static void build_viewok(nodus_t3_msg_t *m, const nodus_witness_t *w,
                         const peer_t *from, uint64_t height, uint32_t view,
                         uint64_t nonce, uint64_t ts) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_VIEWOK;
    m->header.round = 1;
    m->header.view = view;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = ts;
    m->header.nonce = nonce;

    m->viewok.height = height;
    m->viewok.view = view;
    memset(m->viewok.set_hash, 0x9A, sizeof(m->viewok.set_hash));
    m->viewok.n_entries = 1;
    memcpy(m->viewok.entries[0].voter_id, from->id,
           NODUS_T3_WITNESS_ID_LEN);
    memset(m->viewok.entries[0].signature, 0x9B, NODUS_SIG_BYTES);
}

/** One w_viewok_q from `from`. `height_hint` authorises nothing — the
 *  handler answers about the proof IT holds — so it is our own next
 *  height and nothing depends on it. */
static void build_viewok_req(nodus_t3_msg_t *m, const nodus_witness_t *w,
                             const peer_t *from, uint64_t nonce,
                             uint64_t ts) {
    memset(m, 0, sizeof(*m));
    m->type = NODUS_T3_VIEWOK_REQ;
    m->header.round = 1;
    m->header.view = 0;
    memcpy(m->header.sender_id, from->id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(m->header.chain_id, w->chain_id, sizeof(m->header.chain_id));
    m->header.timestamp = ts;
    m->header.nonce = nonce;

    m->viewok_q.height_hint = 1;
}

/* ═══════════════════════════════════════════════════════════════════
 * §1 — THE ANTI-VACUITY FLOOR.
 *
 * Runs first and asserts the two things every later section's meaning
 * rests on: an ordinary honest nonce IS refused on a genuine repeat, and
 * a fresh nonce IS still accepted. Without this pair a build in which the
 * cache refused EVERYTHING, or recorded NOTHING, would pass several of
 * the sections below.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_vacuity_floor(void) {
    printf("\n§1 the floor — a genuine repeat is refused, a fresh nonce "
           "is accepted\n");

    char dir[] = "/tmp/test_rpc_floor_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x11);

    uint64_t now = nodus_time_now();
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: the governing committee at height 1 has eight "
          "members, so every frame here is from an authorized sender");
    CHECK(nodus_witness_block_height(w) == 0,
          "precondition: the fixture chain is empty, so height 1 is our "
          "own next block and no height guard can fire");

    static char out_first[CAP_BUF];
    static char out_repeat[CAP_BUF];
    static char out_fresh[CAP_BUF];

    int rc1 = deliver(w, &g_peers[P_VACUITY], N_VAC_A, now,
                      out_first, sizeof(out_first));
    CHECK(rc1 == -1 && said(out_first, L_BELOW),
          "ADMITTED: a first-time nonce from a committee member travels "
          "past the committee gate to the F02 batch re-verify (-1 there "
          "is the pre-existing outcome for any unit fixture)");
    CHECK(!said(out_first, L_NONMEMBER) && !said(out_first, L_UNKNOWN) &&
          !said(out_first, L_LOADFAULT),
          "and no committee guard fired on it");

    int rc2 = deliver(w, &g_peers[P_VACUITY], N_VAC_A, now,
                      out_repeat, sizeof(out_repeat));
    CHECK(rc2 == -1 && silent(out_repeat),
          "REFUSED AS A REPLAY: the very same (sender, nonce) is turned "
          "away silently, above every guard that prints — so the record "
          "the admitted leg made is real and the cache still works");

    int rc3 = deliver(w, &g_peers[P_VACUITY], N_VAC_B, now,
                      out_fresh, sizeof(out_fresh));
    CHECK(rc3 == -1 && said(out_fresh, L_BELOW),
          "AND IT IS NOT REFUSING EVERYTHING: a different nonce from the "
          "same sender is admitted — the refusal above is a decision "
          "about the KEY, not a wall");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §2 — RECORD AFTER THE GATES: a refused frame consumes NO slot.
 *
 * THE DEFECT: all six T3 consumers inserted the nonce ABOVE their own
 * chain_id and committee checks, so an unauthorised sender spent the
 * capacity that protects authorised ones — and, as the O15M note in
 * handle_newview names, a frame refused for a TRANSIENT reason burned the
 * nonce of the delivery that would have succeeded.
 *
 * THE OBSERVABLE, named as the header demands: the SAME (sender, nonce)
 * is delivered TWICE, and the only thing that moves between the legs is
 * the COMMITTEE. Leg 1 is refused by the gate; leg 2, with the sender now
 * seated, must reach the F02 verify. Under the shipped record-above-the-
 * gate order leg 2 would instead be refused SILENTLY as a replay — so
 * this section is a residue-independent revert detector, and the third
 * leg proves leg 2 did record.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_record_after_gates(void) {
    printf("\n§2 record-after-the-gates — a refused frame consumes no "
           "slot\n");

    char dir[] = "/tmp/test_rpc_gate_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x22);

    uint64_t now = nodus_time_now();

    /* BASE committee: peers [0..8). Peer 8 is on the roster and outside
     * it — one Dilithium keypair plus one DHT put, per BUGS.md O15N-L4. */
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: the committee at height 1 EXCLUDES the sender "
          "this leg uses");

    static char out_refused[CAP_BUF];
    static char out_seated[CAP_BUF];
    static char out_third[CAP_BUF];

    int rc1 = deliver(w, &g_peers[P_OUTSIDER], N_GATE, now,
                      out_refused, sizeof(out_refused));
    CHECK(rc1 == -1 && said(out_refused, L_NONMEMBER),
          "REFUSED BY THE COMMITTEE GATE: a roster member outside the "
          "committee is turned away, and the refusal NAMES that gate");
    CHECK(!said(out_refused, L_BELOW),
          "and nothing below the gate ran");

    /* THE ONE THING THAT MOVES. Same sender, same nonce, same timestamp,
     * same height — the committee now seats peer 8. */
    prime_committee(w, /*height*/ 1, N_COMMITTEE_WIDE);
    count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE_WIDE,
          "the committee is widened to nine and now CONTAINS that sender "
          "— the only difference between the two legs");

    int rc2 = deliver(w, &g_peers[P_OUTSIDER], N_GATE, now,
                      out_seated, sizeof(out_seated));
    CHECK(rc2 == -1 && said(out_seated, L_BELOW),
          "THE DEFECT IS CLOSED: the SAME (sender, nonce) is now admitted "
          "all the way to the F02 verify — so the refusal above consumed "
          "no slot in the replay cache");
    CHECK(!silent(out_seated) && !said(out_seated, L_NONMEMBER),
          "and it was NOT refused silently, which is what the shipped "
          "record-above-the-gate order would have produced");

    /* CONTROL. Without it, a build that recorded NOTHING anywhere would
     * pass the leg above. */
    int rc3 = deliver(w, &g_peers[P_OUTSIDER], N_GATE, now,
                      out_third, sizeof(out_third));
    CHECK(rc3 == -1 && silent(out_third),
          "CONTROL: a THIRD delivery of the same (sender, nonce) IS "
          "refused as a replay — so the admitted leg did record, and the "
          "admission is a decision about authorization, not a cache that "
          "has stopped writing");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §3 — "OLDEST" IS THE INSERT ORDER, NOT THE WIRE TIMESTAMP.
 *
 * One sender inserts two entries in a KNOWN order with INVERTED wire
 * timestamps:
 *
 *     A  inserted FIRST,  stamped now - 50   (the NEWER wire stamp)
 *     B  inserted SECOND, stamped now - 100  (the OLDER wire stamp)
 *
 * The sender is then driven to exactly ONE eviction. Ranking by the
 * node-local sequence evicts A; ranking by the wire timestamp — the
 * shipped rule, and the field the sender chooses — would evict B. The
 * pair separates the two, and B's leg is the one that goes red if the
 * ordering key is ever put back on the timestamp.
 *
 * ARITHMETIC, so the "exactly one eviction" claim can be checked: after A
 * and B the sender holds 2 entries. nonce_record evicts when the count
 * BEFORE the insert is already at CAP_MIRROR, so flood frame i sees a
 * count of i + 1 and the first eviction is at i == CAP_MIRROR - 1. A
 * flood of exactly CAP_MIRROR - 1 frames therefore fires exactly one.
 *
 * ORDER OF THE TWO ASSERTIONS IS LOAD-BEARING: re-delivering A re-records
 * it, which puts the sender back at its cap and evicts the new oldest —
 * which is B. So B must be asserted FIRST.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_ordering_is_local(void) {
    printf("\n§3 the ordering key — insert order, not the wire "
           "timestamp\n");

    char dir[] = "/tmp/test_rpc_order_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x33);

    uint64_t now = nodus_time_now();
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: the sender is a committee member, so every frame "
          "here reaches the record");

    static char out_a[CAP_BUF];
    static char out_b[CAP_BUF];
    static char out_b2[CAP_BUF];
    static char out_a2[CAP_BUF];

    int rc_a = deliver(w, &g_peers[P_ORDER], N_ORDER_A, now - 50,
                       out_a, sizeof(out_a));
    CHECK(rc_a == -1 && said(out_a, L_BELOW),
          "A is recorded FIRST and carries the NEWER wire stamp "
          "(now - 50)");

    int rc_b = deliver(w, &g_peers[P_ORDER], N_ORDER_B, now - 100,
                       out_b, sizeof(out_b));
    CHECK(rc_b == -1 && said(out_b, L_BELOW),
          "B is recorded SECOND and carries the OLDER wire stamp "
          "(now - 100) — the two orders now disagree");

    flood(w, &g_peers[P_ORDER], now, N_FLOOD_BASE, CAP_MIRROR - 1);

    /* B FIRST — see the header note on assertion order. */
    int rc_b2 = deliver(w, &g_peers[P_ORDER], N_ORDER_B, now - 100,
                        out_b2, sizeof(out_b2));
    CHECK(rc_b2 == -1 && silent(out_b2),
          "B SURVIVED and is still refused as a replay — the entry with "
          "the OLDEST WIRE STAMP was NOT the victim, so the sender's own "
          "timestamp does not decide what leaves the cache");

    int rc_a2 = deliver(w, &g_peers[P_ORDER], N_ORDER_A, now - 50,
                        out_a2, sizeof(out_a2));
    CHECK(rc_a2 == -1 && said(out_a2, L_BELOW),
          "A WAS EVICTED and is admitted again — the entry inserted FIRST "
          "is the one that left, which is the node-local sequence and "
          "nothing else");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §4 — A FLOODER EVICTS ONLY ITSELF.
 *
 * The bystander records one nonce; the flooder records one (its oldest)
 * and then floods its whole share. Exactly one eviction fires and it must
 * land on the FLOODER's own first entry, never on the bystander's.
 *
 * ARITHMETIC: after its first entry the flooder holds 1, so flood frame i
 * sees a count of i and the first eviction is at i == CAP_MIRROR. A flood
 * of exactly CAP_MIRROR frames fires exactly one.
 *
 * BOTH LEGS ARE REQUIRED. "The bystander survived" alone would pass on a
 * build that evicts nothing at all; "the flooder's oldest came back"
 * alone would pass on a build that evicts indiscriminately.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_flooder_evicts_itself(void) {
    printf("\n§4 a flooder evicts ONLY ITSELF\n");

    char dir[] = "/tmp/test_rpc_self_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x44);

    uint64_t now = nodus_time_now();
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: BOTH senders are committee members — the flooder "
          "is an authorized insider, which is the only sender class that "
          "can reach the record at all");

    static char out_h[CAP_BUF];
    static char out_f[CAP_BUF];
    static char out_h2[CAP_BUF];
    static char out_f2[CAP_BUF];

    int rc_h = deliver(w, &g_peers[P_HONEST_SELF], N_SELF_HON, now,
                       out_h, sizeof(out_h));
    CHECK(rc_h == -1 && said(out_h, L_BELOW),
          "the bystander records one nonce");

    int rc_f = deliver(w, &g_peers[P_FLOOD_SELF], N_SELF_FIRST, now,
                       out_f, sizeof(out_f));
    CHECK(rc_f == -1 && said(out_f, L_BELOW),
          "the flooder records one nonce — this is the entry it is about "
          "to destroy");

    flood(w, &g_peers[P_FLOOD_SELF], now, N_FLOOD_BASE, CAP_MIRROR);

    int rc_h2 = deliver(w, &g_peers[P_HONEST_SELF], N_SELF_HON, now,
                        out_h2, sizeof(out_h2));
    CHECK(rc_h2 == -1 && silent(out_h2),
          "THE BYSTANDER IS UNTOUCHED: its nonce is still refused as a "
          "replay after a full share has been flooded past it");

    int rc_f2 = deliver(w, &g_peers[P_FLOOD_SELF], N_SELF_FIRST, now,
                        out_f2, sizeof(out_f2));
    CHECK(rc_f2 == -1 && said(out_f2, L_BELOW),
          "AND THE EVICTION REALLY HAPPENED: the FLOODER's own oldest "
          "nonce is admitted again — it paid for its flood out of its own "
          "budget");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §5 — THE ATTACK (BUGS.md O15N-L1). RUNS LAST, AND IT IS THE ROW THAT
 *      MUST GO RED IF THE PRODUCTION CHANGE IS REVERTED.
 *
 * The victim records one nonce, stamped `now - 150` — the ONLY
 * past-stamped entry in this whole file, which makes it the unique global
 * minimum by wire timestamp. The attacker then floods FLOOD_BIG frames,
 * enough to exceed the 10000-entry GLOBAL cap this phase deleted even
 * from an empty table.
 *
 * On the shipped code that flood drives nonce_evict_oldest, which frees
 * the entire bucket holding the smallest wire timestamp — the victim's —
 * and the victim's captured frame becomes replayable. On the fixed code
 * the attacker can only spend its own share, and the victim's entry is
 * untouchable.
 *
 * WHY THE FLOOD IS STAMPED AT `now` AND NOT IN THE FUTURE: see the note
 * in HOW IT CAN LIE. A future stamp underflows the TTL subtraction and
 * the entry is purged on the next sweep of its bucket, so a far-future
 * flood never fills a table and this section would pass on the reverted
 * build while proving nothing.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_the_attack(void) {
    printf("\n§5 THE ATTACK — a flood cannot evict an honest sender's "
           "nonce\n");

    char dir[] = "/tmp/test_rpc_attack_XXXXXX";
    nodus_witness_t *w = fixture(dir, 0x55);

    uint64_t now = nodus_time_now();
    prime_committee(w, /*height*/ 1, N_COMMITTEE);
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_COMMITTEE,
          "precondition: attacker and victim are BOTH committee members "
          "— the strongest form of the attack, since the committee gate "
          "cannot help here");

    static char out_v1[CAP_BUF];
    static char out_v2[CAP_BUF];
    static char out_v3[CAP_BUF];
    static char out_v4[CAP_BUF];

    int rc1 = deliver(w, &g_peers[P_HONEST_BIG], N_BIG_HON, now - 150,
                      out_v1, sizeof(out_v1));
    CHECK(rc1 == -1 && said(out_v1, L_BELOW),
          "the victim's frame is admitted and recorded");

    int rc2 = deliver(w, &g_peers[P_HONEST_BIG], N_BIG_HON, now - 150,
                      out_v2, sizeof(out_v2));
    CHECK(rc2 == -1 && silent(out_v2),
          "BEFORE THE FLOOD: replaying the victim's captured frame is "
          "refused — this is the protection the attack exists to remove");

    flood(w, &g_peers[P_FLOOD_BIG], now, N_FLOOD_BASE, FLOOD_BIG);

    int rc3 = deliver(w, &g_peers[P_HONEST_BIG], N_BIG_HON, now - 150,
                      out_v3, sizeof(out_v3));
    CHECK(rc3 == -1 && silent(out_v3),
          "AFTER THE FLOOD: the victim's captured frame is STILL refused "
          "as a replay — the attacker spent its own share and could not "
          "reach the victim's. THIS IS THE DEFECT; on the shipped code "
          "the flood freed the victim's bucket and this replay succeeded");

    int rc4 = deliver(w, &g_peers[P_HONEST_BIG], N_BIG_FRESH, now,
                      out_v4, sizeof(out_v4));
    CHECK(rc4 == -1 && said(out_v4, L_BELOW),
          "AND THE VICTIM IS NOT LOCKED OUT: a fresh nonce from the same "
          "sender is still admitted, so the flood did not simply wall the "
          "cache off");

    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §6..§10 — THE FIVE RECORD SITES THAT WERE PLACED BY INSPECTION.
 *
 * Until O15P Faz 2 exactly ONE of the six nonce_record call sites was
 * driven (handle_commit, by §1..§5). The other five were written below
 * the same committee gate and never executed by a test, so a site in the
 * wrong place — above its gate, or below the return that would have made
 * it unreachable — would have shipped silently.
 *
 * Each section is the same three legs, and all three are required:
 *   (a) ADMITTED — a well-formed frame travels BELOW the record site,
 *       identified POSITIVELY by a line that guard prints or by rc == 0;
 *   (b) REPLAY   — the IDENTICAL frame is refused the second time;
 *   (c) FRESH    — the same frame with a different nonce is admitted
 *       again, which is what excludes "this handler refuses everything
 *       for an unrelated reason" and makes (b) a statement about the KEY.
 *
 * All five share `g_ext`, and no two use the same index (see the header's
 * identity partition). Each builds its own fixture, its own chain
 * database and its own chain_id.
 * ═══════════════════════════════════════════════════════════════════ */

/** Every §6..§10 fixture: this node is g_ext[0], the roster is the whole
 *  eight-peer ext array, and the committee at height 1 is the same eight.
 *  The chain stays empty, so our next height is 1 and every committee
 *  lookup lands in the epoch containing 1 at any DNAC_EPOCH_LENGTH. */
static nodus_witness_t *ext_fixture(char *dir_template, uint8_t tag) {
    nodus_witness_t *w =
        fixture_from(dir_template, tag, &g_ext[0], g_ext, N_EXT);
    prime_committee_from(w, /*height*/ 1, g_ext, N_EXT);

    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == N_EXT,
          "precondition: the committee governing height 1 is the whole "
          "eight-peer roster, so every sender below is AUTHORIZED and the "
          "committee gate cannot be the refuser");
    CHECK(nodus_witness_block_height(w) == 0,
          "precondition: the fixture chain is empty, so our next block is "
          "height 1 and every height-derived lookup agrees on it");
    return w;
}

/* ── §6 — the PROPOSE record site (nodus_witness_bft.c handle_propose,
 *        immediately below the committee-derived LEADER check).
 *
 * THE ADMITTED LEG IS IDENTIFIED BY THE A2 HEIGHT GATE, which sits below
 * the record and prints its own line. The proposal is well-formed in
 * every respect the gates above the record examine — right chain_id,
 * right sender, and the sender IS the committee-derived leader for the
 * view we hold — and carries a block_height that is not our next one, so
 * it is refused by a guard that NAMES ITSELF and writes no round state.
 * That last property is what makes leg (c) meaningful: a proposal that
 * had been ACCEPTED would leave the round non-IDLE, and leg (c) would
 * then die at the round-in-progress gate ABOVE the record, proving
 * nothing.
 *
 * THE VIEW IS CHOSEN AT RUNTIME so the leader is a NAMED identity at any
 * DNAC_EPOCH_LENGTH. leader_index is (epoch + view) % n; the section
 * solves that for view given the epoch containing height 1, then asks the
 * PRODUCTION function and asserts the answer. A hard-coded view would
 * make the "the sender is the leader" precondition depend on the epoch
 * length and could silently select a peer another section owns.
 * ────────────────────────────────────────────────────────────────── */
static void section_record_propose(void) {
    printf("\n§6 the PROPOSE record site\n");

    char dir[] = "/tmp/test_rpc_propose_XXXXXX";
    nodus_witness_t *w = ext_fixture(dir, 0x66);

    uint64_t now = nodus_time_now();
    uint64_t epoch = 1ULL / (uint64_t)DNAC_EPOCH_LENGTH;
    uint32_t view = (uint32_t)(((uint64_t)P_EXT_PROPOSE + (uint64_t)N_EXT
                                - (epoch % (uint64_t)N_EXT))
                               % (uint64_t)N_EXT);
    CHECK(nodus_witness_bft_leader_index(epoch, view, N_EXT) == P_EXT_PROPOSE,
          "precondition: the PRODUCTION leader index names this section's "
          "own peer as the leader for the chosen view — asked, not "
          "assumed, and solved for the epoch this build's "
          "DNAC_EPOCH_LENGTH puts height 1 in");

    /* The view we HOLD equals the view the proposal names, so the O15N
     * view-equality gate below the record cannot be the refuser and no
     * VIEW_OK request is triggered. */
    w->current_view = view;

    static char out_a[CAP_BUF];
    static char out_b[CAP_BUF];
    static char out_c[CAP_BUF];

    nodus_t3_msg_t m;
    /* block_height 99 is NOT our next height (1), so the frame lands on
     * the A2 gate — the first thing below the record that prints. */
    build_propose(&m, w, &g_ext[P_EXT_PROPOSE], view, /*bh*/ 99,
                  N_PROP_A, now);

    cap_begin();
    int rc_a = nodus_witness_bft_handle_propose(w, &m);
    cap_end(out_a, sizeof(out_a));
    CHECK(rc_a == -1 && said(out_a, L_PROP_BELOW),
          "ADMITTED: the proposal travelled past the leader/committee "
          "block — and therefore past the nonce_record that follows it — "
          "to the A2 height gate, which named itself");
    CHECK(!said(out_a, L_PROP_NOLEAD) && !said(out_a, L_PROP_NOSEND) &&
          !said(out_a, L_PROP_INROUND) && !said(out_a, L_PROP_VIEW) &&
          !said(out_a, L_LOADFAULT) && !said(out_a, L_CHAINID),
          "and NO guard above the record fired — not the leader check, "
          "not the roster check, not the round-in-progress gate, not the "
          "view-equality gate, not a committee fault, not chain_id");

    cap_begin();
    int rc_b = nodus_witness_bft_handle_propose(w, &m);
    cap_end(out_b, sizeof(out_b));
    CHECK(rc_b == -1 && silent(out_b),
          "REFUSED AS A REPLAY: the byte-identical proposal is turned "
          "away silently, above every guard that prints — so the PROPOSE "
          "record site really recorded");

    m.header.nonce = N_PROP_B;
    cap_begin();
    int rc_c = nodus_witness_bft_handle_propose(w, &m);
    cap_end(out_c, sizeof(out_c));
    CHECK(rc_c == -1 && said(out_c, L_PROP_BELOW),
          "AND IT IS NOT REFUSING EVERYTHING: the same proposal with a "
          "FRESH nonce is admitted again — the refusal above is a "
          "decision about the KEY");

    CHECK(w->round_state.phase == NODUS_W_PHASE_IDLE && w->current_round == 0,
          "and no round was ever entered, so leg (c) met the same gates "
          "leg (a) did and the three legs are comparable");

    fixture_free(w, dir);
}

/* ── §7 — the VOTE record site (bft_handle_vote_inner, immediately below
 *        the committee-membership gate).
 *
 * THE ADMITTED LEG IS IDENTIFIED BY THE C5 CERTIFICATE CHECK, the first
 * guard below the record. The vote is an APPROVE PREVOTE for the live
 * round's own target, from a committee member, at the round's round and
 * view — everything the gates above the record examine — and carries an
 * all-zero cert_sig, so the C5 check refuses it BY NAME and the vote is
 * never recorded in the round's vote array. That last part is why leg (c)
 * works: had the vote been counted, the pubkey dedup ABOVE the record
 * would swallow leg (c) with rc 0 and the section would prove nothing.
 *
 * THE ROUND IS SET UP BY HAND, and only the fields the gates read. That
 * is not the subject here — the subject is whether the record site fires
 * — and driving a real proposal in would put handle_propose's gates
 * between the fixture and the vote.
 *
 * THE VOTE BUFFER IS DELIBERATELY NOT ON THIS PATH. handle_vote diverts
 * near-future frames to bft_vote_buffer_insert and returns 0 WITHOUT ever
 * meeting a committee gate or a record. hdr->round equals the live
 * round's, and the type is PREVOTE while the phase is PREVOTE, so neither
 * the future_round nor the early_precommit condition can hold.
 * ────────────────────────────────────────────────────────────────── */
static void section_record_vote(void) {
    printf("\n§7 the VOTE record site\n");

    char dir[] = "/tmp/test_rpc_vote_XXXXXX";
    nodus_witness_t *w = ext_fixture(dir, 0x67);

    uint64_t now = nodus_time_now();

    /* A live PREVOTE round at our own next height. */
    uint8_t target[NODUS_T3_TX_HASH_LEN];
    memset(target, 0xC7, sizeof(target));
    w->current_round = 1;
    memset(&w->round_state, 0, sizeof(w->round_state));
    w->round_state.round = 1;
    w->round_state.view = w->current_view;      /* both 0 */
    w->round_state.phase = NODUS_W_PHASE_PREVOTE;
    w->round_state.block_height = 1;
    memcpy(w->round_state.tx_hash, target, NODUS_T3_TX_HASH_LEN);
    w->round_state.phase_start_time = now * 1000ULL;

    CHECK(w->round_state.prevote_count == 0,
          "precondition: the round holds no votes, so the pubkey dedup "
          "above the record cannot fire on any of the three legs");

    static char out_a[CAP_BUF];
    static char out_b[CAP_BUF];
    static char out_c[CAP_BUF];

    nodus_t3_msg_t m;
    build_prevote(&m, w, &g_ext[P_EXT_VOTE], target, N_VOTE_A, now);

    cap_begin();
    int rc_a = nodus_witness_bft_handle_vote(w, &m);
    cap_end(out_a, sizeof(out_a));
    CHECK(rc_a == -1 && said(out_a, L_VOTE_BELOW),
          "ADMITTED: the vote travelled past the committee gate — and "
          "therefore past the nonce_record that follows it — to the C5 "
          "certificate check, which named itself");
    CHECK(!said(out_a, L_VOTE_NOSEND) && !said(out_a, L_VOTE_NOMEM) &&
          !said(out_a, L_VOTE_COMM) && !said(out_a, L_VOTE_HASH) &&
          !said(out_a, L_CHAINID),
          "and NO guard above the record fired — not the roster check, "
          "not the committee gate, not a committee fault, not the "
          "vote-target check, not chain_id");
    CHECK(w->round_state.prevote_count == 0,
          "and the vote was DROPPED rather than counted, so the dedup "
          "above the record stays inert for the legs below");

    cap_begin();
    int rc_b = nodus_witness_bft_handle_vote(w, &m);
    cap_end(out_b, sizeof(out_b));
    CHECK(rc_b == -1 && silent(out_b),
          "REFUSED AS A REPLAY: the byte-identical vote is turned away "
          "silently at the top of handle_vote — so the VOTE record site, "
          "which lives inside bft_handle_vote_inner and not beside the "
          "check, really recorded");

    m.header.nonce = N_VOTE_B;
    cap_begin();
    int rc_c = nodus_witness_bft_handle_vote(w, &m);
    cap_end(out_c, sizeof(out_c));
    CHECK(rc_c == -1 && said(out_c, L_VOTE_BELOW),
          "AND IT IS NOT REFUSING EVERYTHING: the same vote with a FRESH "
          "nonce reaches the same guard again");

    fixture_free(w, dir);
}

/* ── §8 — the VIEW_CHANGE record site (handle_viewchg, below the
 *        committee gate and above the D9 record upsert).
 *
 * THIS SECTION DOES NOT REST ON SILENCE. Every exit above the record
 * returns -1; the first thing below it — "must be for a future view" —
 * returns 0. So rc alone separates "reached the record" from "refused as
 * a replay", which is a stronger discriminator than §1..§7 have.
 *
 * The frame names a view we already hold, so it stops at that return
 * without touching w->view_changes. The section asserts view_change_count
 * stayed 0 afterwards, which is a second, non-stderr witness that no
 * state below the record was written and that the three legs are
 * comparable.
 * ────────────────────────────────────────────────────────────────── */
static void section_record_viewchg(void) {
    printf("\n§8 the VIEW_CHANGE record site\n");

    char dir[] = "/tmp/test_rpc_viewchg_XXXXXX";
    nodus_witness_t *w = ext_fixture(dir, 0x68);

    uint64_t now = nodus_time_now();
    CHECK(w->current_view == 0 && w->view_change_count == 0,
          "precondition: we hold view 0 and no view-change record exists");

    static char out_a[CAP_BUF];
    static char out_b[CAP_BUF];
    static char out_c[CAP_BUF];

    nodus_t3_msg_t m;
    /* new_view 0 is not ahead of the view we hold, so the frame stops at
     * the first return below the record — rc 0, no state written. */
    build_viewchg(&m, w, &g_ext[P_EXT_VIEWCHG], /*new_view*/ 0,
                  N_VCHG_A, now);

    cap_begin();
    int rc_a = nodus_witness_bft_handle_viewchg(w, &m);
    cap_end(out_a, sizeof(out_a));
    CHECK(rc_a == 0,
          "ADMITTED: rc 0 is reachable ONLY below the record — every exit "
          "above it returns -1 — so the frame passed the committee gate "
          "and the nonce_record that follows it");
    CHECK(!said(out_a, L_VCHG_NOMEM) && !said(out_a, L_LOADFAULT) &&
          !said(out_a, L_CHAINID),
          "and no guard above the record fired");

    cap_begin();
    int rc_b = nodus_witness_bft_handle_viewchg(w, &m);
    cap_end(out_b, sizeof(out_b));
    CHECK(rc_b == -1 && silent(out_b),
          "REFUSED AS A REPLAY: the byte-identical VIEW_CHANGE now returns "
          "-1 instead of 0 — so the VIEW_CHANGE record site really "
          "recorded");

    m.header.nonce = N_VCHG_B;
    cap_begin();
    int rc_c = nodus_witness_bft_handle_viewchg(w, &m);
    cap_end(out_c, sizeof(out_c));
    CHECK(rc_c == 0,
          "AND IT IS NOT REFUSING EVERYTHING: the same VIEW_CHANGE with a "
          "FRESH nonce is admitted again");

    CHECK(w->view_change_count == 0,
          "and no voter record was upserted by any leg — the frames "
          "stopped at the same place, so the three are comparable");

    fixture_free(w, dir);
}

/* ── §9 — the VIEW_OK record site (handle_viewok, below the committee
 *        gate and above the direct verify and the accumulator fold).
 *
 * Same rc-based discriminator as §8: every exit above the record returns
 * -1 and every path below it returns 0.
 *
 * THE BUNDLE IS THE ORDINARY BROADCAST SHAPE — n_entries == 1 — for a
 * view we already hold. n_entries >= 2 is what triggers the direct
 * verify_view_proof, and `v->view > current_view` is what makes the
 * accumulator try to apply; neither holds, so no Dilithium work happens
 * below the record and the legs cost nothing beyond the fold. Leg (c)
 * folds the SAME voter, which the accumulator recognises as already
 * present, so it takes the "nothing new" return — still 0.
 * ────────────────────────────────────────────────────────────────── */
static void section_record_viewok(void) {
    printf("\n§9 the VIEW_OK record site\n");

    char dir[] = "/tmp/test_rpc_viewok_XXXXXX";
    nodus_witness_t *w = ext_fixture(dir, 0x69);

    uint64_t now = nodus_time_now();
    CHECK(w->current_view == 0 && !w->viewok_acc.active,
          "precondition: we hold view 0 and the accumulator is empty, so "
          "the bundle's view cannot be ahead of ours and no proof "
          "verification runs below the record");

    static char out_a[CAP_BUF];
    static char out_b[CAP_BUF];
    static char out_c[CAP_BUF];

    nodus_t3_msg_t m;
    build_viewok(&m, w, &g_ext[P_EXT_VIEWOK], /*height*/ 1, /*view*/ 0,
                 N_VOK_A, now);

    cap_begin();
    int rc_a = nodus_witness_bft_handle_viewok(w, &m);
    cap_end(out_a, sizeof(out_a));
    CHECK(rc_a == 0,
          "ADMITTED: rc 0 is reachable ONLY below the record — every exit "
          "above it returns -1 — so the bundle passed the committee gate "
          "and the nonce_record that follows it");
    CHECK(!said(out_a, L_VOK_NOMEM) && !said(out_a, L_VOK_NOCOMM) &&
          !said(out_a, L_LOADFAULT) && !said(out_a, L_CHAINID),
          "and no guard above the record fired");

    cap_begin();
    int rc_b = nodus_witness_bft_handle_viewok(w, &m);
    cap_end(out_b, sizeof(out_b));
    CHECK(rc_b == -1 && silent(out_b),
          "REFUSED AS A REPLAY: the byte-identical bundle now returns -1 "
          "instead of 0 — so the VIEW_OK record site really recorded");

    m.header.nonce = N_VOK_B;
    cap_begin();
    int rc_c = nodus_witness_bft_handle_viewok(w, &m);
    cap_end(out_c, sizeof(out_c));
    CHECK(rc_c == 0,
          "AND IT IS NOT REFUSING EVERYTHING: the same bundle with a "
          "FRESH nonce is admitted again");

    fixture_free(w, dir);
}

/* ── §10 — the VIEW_OK_REQUEST record site (handle_viewok_req, below the
 *         committee gate and above the per-roster-slot response limiter).
 *
 * THIS SECTION HAS A NON-STDERR WITNESS AS WELL AS rc. The first thing
 * below the record is the limiter, and the last thing on the success path
 * writes w->viewok_rsp_sent_ms[roster slot]. So "reached below the
 * record" is observable as a stamp on this node.
 *
 * ⚠ THE STAMP IS CLEARED BEFORE THE REPLAY LEG, AND THAT IS LOAD-BEARING.
 * The limiter refuses with a SILENT -1, exactly like the replay check. If
 * the stamp were left set from leg (a), a build whose record site had
 * been DELETED would have leg (b) refused by the LIMITER and the section
 * would still pass. Clearing it means the only thing that can refuse leg
 * (b) is the replay check.
 *
 * THE CONNECTION IS REAL ENOUGH AND TOUCHES NO FILE DESCRIPTOR. The
 * handler answers by encoding a T3 frame and calling nodus_tcp_send. A
 * conn with `auth_required` set and its auth state at the calloc'd
 * NODUS_CONN_AUTH_NONE takes that function's "queue while auth is in
 * progress" branch, which appends the encoded frame to a heap buffer and
 * returns 0 — a legitimate connection state, and the fd (0 on a calloc'd
 * struct, i.e. stdin) is never written to.
 * ────────────────────────────────────────────────────────────────── */
static void section_record_viewok_req(void) {
    printf("\n§10 the VIEW_OK_REQUEST record site\n");

    char dir[] = "/tmp/test_rpc_vokq_XXXXXX";
    nodus_witness_t *w = ext_fixture(dir, 0x6A);

    uint64_t now = nodus_time_now();

    /* "Nothing to say is a correct answer" — the handler returns -1 above
     * the committee gate while it holds no proof, so a retained proof is a
     * precondition, not a subject. Its contents are never verified on
     * this path; only its height selects the committee. */
    w->viewok_proof.active = true;
    w->viewok_proof.height = 1;
    w->viewok_proof.view = 0;
    memset(w->viewok_proof.set_hash, 0xA1, sizeof(w->viewok_proof.set_hash));
    w->viewok_proof.n_entries = 1;
    memcpy(w->viewok_proof.entries[0].voter_id, g_ext[0].id,
           NODUS_T3_WITNESS_ID_LEN);
    memset(w->viewok_proof.entries[0].signature, 0xA2, NODUS_SIG_BYTES);

    nodus_tcp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) { fprintf(stderr, "conn alloc\n"); exit(1); }
    conn->auth_required = true;   /* auth_state stays NODUS_CONN_AUTH_NONE */

    CHECK(w->viewok_rsp_sent_ms[P_EXT_VOKQ] == 0,
          "precondition: no answer has been sent to this roster slot, so "
          "the response limiter below the record cannot fire");

    static char out_a[CAP_BUF];
    static char out_b[CAP_BUF];
    static char out_c[CAP_BUF];

    nodus_t3_msg_t m;
    build_viewok_req(&m, w, &g_ext[P_EXT_VOKQ], N_VOKQ_A, now);

    cap_begin();
    int rc_a = nodus_witness_bft_handle_viewok_req(w, conn, &m);
    cap_end(out_a, sizeof(out_a));
    CHECK(rc_a == 0 && said(out_a, L_VOKQ_BELOW),
          "ADMITTED: the request travelled past the committee gate — and "
          "therefore past the nonce_record that follows it — all the way "
          "to the answer, which named itself");
    CHECK(w->viewok_rsp_sent_ms[P_EXT_VOKQ] != 0,
          "and the response limiter was stamped, which is a witness on "
          "this node's own state rather than on a log line");

    /* ⚠ REQUIRED before the replay leg — see the section header. */
    w->viewok_rsp_sent_ms[P_EXT_VOKQ] = 0;

    cap_begin();
    int rc_b = nodus_witness_bft_handle_viewok_req(w, conn, &m);
    cap_end(out_b, sizeof(out_b));
    CHECK(rc_b == -1 && silent(out_b),
          "REFUSED AS A REPLAY: the byte-identical request is turned away "
          "silently — so the VIEW_OK_REQUEST record site really recorded");
    CHECK(w->viewok_rsp_sent_ms[P_EXT_VOKQ] == 0,
          "and NOTHING below the record ran: the limiter stamp we cleared "
          "is still clear, so the refusal came from above it and not from "
          "the limiter itself");

    m.header.nonce = N_VOKQ_B;
    cap_begin();
    int rc_c = nodus_witness_bft_handle_viewok_req(w, conn, &m);
    cap_end(out_c, sizeof(out_c));
    CHECK(rc_c == 0 && said(out_c, L_VOKQ_BELOW),
          "AND IT IS NOT REFUSING EVERYTHING: the same request with a "
          "FRESH nonce is answered again");

    free(conn->pending_buf);      /* the queued frames from legs (a), (c) */
    free(conn);
    fixture_free(w, dir);
}

/* ═══════════════════════════════════════════════════════════════════
 * §11 — THE 128-SLOT SENDER TABLE, DRIVEN PAST CAPACITY. RUNS LAST.
 *
 * WHAT THE CODE ACTUALLY DOES, read from nonce_sender_claim rather than
 * assumed, because this section asserts THAT and not something nicer:
 *
 *   1. If a slot already holds this sender, it is returned.
 *   2. Otherwise the FIRST slot that is unused, or used with count == 0,
 *      is repurposed. Such a slot owns no entries, so nothing is lost.
 *   3. If every slot is used AND non-empty, the LEAST RECENTLY ACTIVE one
 *      — smallest `last_seq`, a node-local counter, never a wire value —
 *      is passed to nonce_sender_drop, which FREES EVERY ENTRY that
 *      sender owned and hands the slot to the newcomer.
 *
 * So the honest characterisation is: nothing crashes, the newcomer IS
 * recorded, every other sender keeps its entries, and EXACTLY ONE sender
 * — the least recently active — loses all of its. The production comment
 * says the same and calls the consequence accepted and node-local:
 * "Dropping a slot re-opens self-replay for that one sender until it
 * inserts again."
 *
 * THE HANDLER IS handle_commit, THE ONE §1..§5 ALREADY DRIVE, and that is
 * deliberate: this section's subject is the SLOT TABLE, which is shared by
 * all six record sites, so using the site already established as working
 * keeps the section about the table. §6..§10 are where the other five
 * sites are established.
 *
 * WHY IT TAKES TWO ROSTER SEATINGS. NONCE_MAX_SENDERS, the roster
 * capacity and the committee cache are all NODUS_T3_MAX_WITNESSES = 128,
 * and nonce_record runs only below a committee gate — so ONE seating can
 * authorise at most 128 distinct senders, exactly filling the table. The
 * 129th needs a second seating. The section therefore:
 *
 *   A. seats ov[0..127] and delivers one frame from each;
 *   B. re-seats ov[1..128] and delivers one frame from ov[128];
 *   C. re-seats ov[0..127] and asks who survived.
 *
 * WHY STEP A IS DETERMINISTIC WHATEVER §1..§10 LEFT BEHIND. `nonce_seq_next`
 * is monotonic and never reset, so every entry this section makes is newer
 * than every entry any earlier section made, and the eviction rule is
 * least-recently-active by that same counter. 128 distinct senders
 * delivered into a 128-slot table therefore evict precisely the earlier
 * sections' slots — however many there were, in whatever order — and
 * leave the table holding EXACTLY ov[0..127]. That state is ASSERTED at
 * the end of step A rather than assumed.
 *
 * ⚠ THE ASSERTION ORDER IN STEP C IS LOAD-BEARING, and it is the same
 * trap §3 documents one level up: re-delivering an evicted sender's frame
 * RE-RECORDS it, which claims a slot and evicts the new least-recently-
 * active sender. So the survivors are asserted BEFORE the victim is
 * re-delivered.
 * ═══════════════════════════════════════════════════════════════════ */
static void section_sender_table_overflow(void) {
    printf("\n§11 the sender table, driven past its 128 slots\n");

    /* ~980 kB of key material: heap, never .bss. */
    peer_t *ov = calloc(N_OV, sizeof(*ov));
    if (!ov) { fprintf(stderr, "ov alloc\n"); exit(1); }
    for (int i = 0; i < N_OV; i++) peer_make(&ov[i]);

    char dir[] = "/tmp/test_rpc_slots_XXXXXX";
    /* This node is ov[P_OV_SELF] and is deliberately NOT on the roster:
     * the roster holds exactly NODUS_T3_MAX_WITNESSES sender identities
     * and has no seat left for it. Nothing on the handle_commit path
     * above the F02 batch re-verify reads w->my_id. */
    nodus_witness_t *w = fixture_from(dir, 0x7B, &ov[P_OV_SELF],
                                      ov, SLOTS_MIRROR);
    prime_committee_from(w, /*height*/ 1, ov, SLOTS_MIRROR);

    uint64_t now = nodus_time_now();
    int count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == SLOTS_MIRROR,
          "precondition: the committee seats all 128 senders, which is "
          "the largest authorised set one fixture can express — the "
          "roster, the committee cache and NONCE_MAX_SENDERS are the same "
          "constant");

    static char out[CAP_BUF];

    /* ── A. FILL EVERY SLOT ──────────────────────────────────────── */
    int admitted = 0;
    for (int i = 0; i < SLOTS_MIRROR; i++) {
        int rc = deliver(w, &ov[i], N_OV_BASE + (uint64_t)i, now,
                         out, sizeof(out));
        if (rc == -1 && said(out, L_BELOW)) admitted++;
    }
    CHECK(admitted == SLOTS_MIRROR,
          "all 128 senders were admitted below the record — the loop is "
          "checked per frame, not sampled, because a single frame that "
          "failed to record would leave a free slot and make the "
          "overflow below unreachable");

    int rc0 = deliver(w, &ov[0], N_OV_BASE + 0, now, out, sizeof(out));
    CHECK(rc0 == -1 && silent(out),
          "the FIRST sender's nonce is refused as a replay, so its slot "
          "is live");
    int rc1 = deliver(w, &ov[1], N_OV_BASE + 1, now, out, sizeof(out));
    CHECK(rc1 == -1 && silent(out),
          "so is the second sender's");
    int rcz = deliver(w, &ov[SLOTS_MIRROR - 1],
                      N_OV_BASE + (uint64_t)(SLOTS_MIRROR - 1), now,
                      out, sizeof(out));
    CHECK(rcz == -1 && silent(out),
          "and so is the LAST one's — the table now holds exactly these "
          "128 senders, whatever the earlier sections left behind, and "
          "the next distinct sender has nowhere to go");

    /* ── B. THE 129th DISTINCT SENDER ────────────────────────────── */
    roster_seat(w, &ov[1], SLOTS_MIRROR);
    prime_committee_from(w, /*height*/ 1, &ov[1], SLOTS_MIRROR);
    count = -1;
    CHECK(committee_probe(w, 1, &count) == 0 && count == SLOTS_MIRROR,
          "the roster and committee are re-seated on ov[1..128], which is "
          "how a 129th AUTHORISED sender becomes expressible at all — a "
          "committee turnover, the very situation the production comment "
          "names as the one that reaches this path");

    int rc_x = deliver(w, &ov[P_OV_EXTRA], N_OV_EXTRA, now,
                       out, sizeof(out));
    CHECK(rc_x == -1 && said(out, L_BELOW),
          "NOTHING CRASHED AND THE NEWCOMER WAS ADMITTED: the 129th "
          "distinct sender is served by dropping a slot, not by refusing "
          "it and not by writing past the array");
    int rc_x2 = deliver(w, &ov[P_OV_EXTRA], N_OV_EXTRA, now,
                        out, sizeof(out));
    CHECK(rc_x2 == -1 && silent(out),
          "AND THE NEWCOMER IS PROTECTED: its own nonce is refused as a "
          "replay, so it really took a slot and really recorded");

    /* ── C. WHO SURVIVED ─────────────────────────────────────────── */
    roster_seat(w, ov, SLOTS_MIRROR);
    prime_committee_from(w, /*height*/ 1, ov, SLOTS_MIRROR);

    /* SURVIVORS FIRST — see the section header on assertion order. */
    int rc1b = deliver(w, &ov[1], N_OV_BASE + 1, now, out, sizeof(out));
    CHECK(rc1b == -1 && silent(out),
          "THE OTHER SENDERS ARE UNTOUCHED: the second sender's nonce is "
          "still refused as a replay, so the overflow did not clear the "
          "table or wipe a bucket");
    int rczb = deliver(w, &ov[SLOTS_MIRROR - 1],
                       N_OV_BASE + (uint64_t)(SLOTS_MIRROR - 1), now,
                       out, sizeof(out));
    CHECK(rczb == -1 && silent(out),
          "and so is the last one's");

    int rc0b = deliver(w, &ov[0], N_OV_BASE + 0, now, out, sizeof(out));
    CHECK(rc0b == -1 && said(out, L_BELOW),
          "AND EXACTLY ONE SENDER PAID: the LEAST RECENTLY ACTIVE one — "
          "the first of the 128, which has the smallest node-local seq — "
          "had its entries freed, so its captured frame is admitted "
          "again. That is the shipped rule (nonce_sender_claim's LRU drop) "
          "and the accepted, node-local residual the production comment "
          "names, not a defect this section is tolerating");

    fixture_free(w, dir);
    free(ov);
}

int main(void) {
    printf("\nO15O Faz 5 / O15P Faz 2 — the replay cache is per sender, "
           "its order is node-local, and all six record sites are "
           "driven\n");

    for (int i = 0; i < N_KEYS; i++) peer_make(&g_peers[i]);
    for (int i = 0; i < N_EXT;  i++) peer_make(&g_ext[i]);

    memset(g_bogus_tx, 0, sizeof(g_bogus_tx));
    g_bogus_tx[0] = (uint8_t)(DNAC_PROTOCOL_VERSION + 1);

    /* ⚠ THE ORDER IS REQUIRED, in two independent ways.
     *
     * §1..§5: small floods first, the one big flood last. The nonce table
     * is a process-global static with no reset hook; under the FIXED code
     * the order is irrelevant because budgets are per sender and the
     * identities are disjoint, but under a REVERTED build a preceding big
     * flood would leave the shared table at its global cap and every
     * later section would evict for reasons unrelated to its subject.
     *
     * §6..§10 are free — each is self-contained on its own identities and
     * asserts no eviction count.
     *
     * §11 MUST BE LAST. It deliberately fills all 128 sender slots with
     * its own identities, which EVICTS everything every earlier section
     * left in the table. Anything scheduled after it would run against an
     * empty cache. See the file header. */
    section_vacuity_floor();
    section_record_after_gates();
    section_ordering_is_local();
    section_flooder_evicts_itself();
    section_the_attack();
    section_record_propose();
    section_record_vote();
    section_record_viewchg();
    section_record_viewok();
    section_record_viewok_req();
    section_sender_table_overflow();

    printf("\nO15O Faz 5 / O15P Faz 2 PASS — all eleven sections ran; no "
           "section is skipped and none is UNREACHED\n");
    return 0;
}
