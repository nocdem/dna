/**
 * Nodus — O15N Faz 2B: the VIEW_OK view-authority primitives.
 *
 * Covers `nodus_witness_bft_sign_view_ok` and
 * `nodus_witness_bft_verify_view_proof` (nodus_witness_bft.h) — the
 * producer and the verifier for a statement that certifies the OUTCOME of
 * a view change ("I observed a view-change quorum for this view, at this
 * height, under this committee") rather than a vote.
 *
 * ── WHAT WOULD BE FALSE IF THIS FILE FAILED ───────────────────────────
 *
 * §B  The signed bytes are 148 and laid out exactly as specified. If this
 *     went red, two builds of this node would sign different structures
 *     for the same statement and neither could verify the other.
 * §C  Production builds THOSE bytes — the KAT is a statement about the
 *     shipped code, not about this file. And the set hash production
 *     signs under is the "DNA.CCSET.v1" derivation, not some private one.
 * §D  Each field is BOUND: chain, height, view, set hash and voter_id.
 *     If any leg went red, a statement harvested from one chain / height
 *     / view / committee / signer would prove a different one — which is
 *     the entire content of the artifact.
 * §E  The threshold is f+1 DISTINCT statements of the committee governing
 *     the CARRIED height. If it went red, either one Byzantine signer
 *     could manufacture view authority (too low), or a sound proof would
 *     be discarded (too high, e.g. read from this node's own bft_config).
 * §F  A FAULT and a VERDICT are distinguishable. -2 means "I cannot
 *     judge"; -1 means "this proof does not hold". Conflating them makes
 *     a node that resolved a different committee denounce statements the
 *     rest of the cluster considers sound.
 * §G  The producer is PURE — signing does not move the view counter or
 *     any round state.
 *
 * ── WHAT IT REQUIRES ──────────────────────────────────────────────────
 *
 * Nothing beyond a default build: no compile flags beyond the
 * NODUS_WITNESS_INTERNAL_API that register_witness_test already supplies,
 * and no environment variables. Every key is derived with
 * qgp_dsa87_keypair_derand from a fixed seed, so a failure reproduces
 * byte-for-byte on any machine — there is no RNG anywhere in this file.
 * Parametric in DNAC_EPOCH_LENGTH: the committee cache is re-primed for
 * the epoch of each height under test, so a short-epoch build behaves
 * identically.
 *
 * ── WHAT IT LEAVES BEHIND ─────────────────────────────────────────────
 *
 * Nothing. Each fixture creates ONE real chain database under a mkdtemp
 * directory in /tmp, closes the sqlite handle and removes the directory
 * on every exit path, including the failure paths.
 *
 * ── HOW IT COULD LIE ──────────────────────────────────────────────────
 *
 * Four specific vacuity paths, each closed by an asserted control:
 *
 *  1. AN EMPTY COMMITTEE. With count 0 the verifier returns -2 before it
 *     looks at a single signature, so every negative leg would "pass"
 *     while measuring nothing. §0 asserts the resolved committee is
 *     non-empty, has exactly VP_COMMITTEE_N members, and is in the ORDER
 *     the fixture primed — order is part of the set hash, so a reordered
 *     resolution is a different committee, not a cosmetic difference.
 *
 *  2. A DEGENERATE THRESHOLD. If f+1 collapsed to 1, "f valid signatures
 *     do not verify" would be the only leg that noticed, and if it
 *     collapsed to 0 nothing would. §0 asserts the derived threshold is
 *     exactly 3 and that 3 is NOT the anti-amplification floor of 2.
 *
 *  3. A VERIFIER THAT REFUSES EVERYTHING. Every negative leg is preceded
 *     by the POSITIVE control in the same fixture — a correct proof
 *     verifies — so a uniformly-refusing verifier fails loudly instead of
 *     passing quietly.
 *
 *  4. A FIXTURE WHOSE ROSTER AND COMMITTEE AGREE. If the transport roster
 *     held exactly the committee, "membership comes from the committee"
 *     would be untestable. The fixture deliberately seats NINE keys in
 *     the roster and primes only SEVEN into the committee, so the two
 *     authorities give DIFFERENT answers (roster quorum 7, committee
 *     quorum 5) and §E/§D can tell which one the code consulted.
 *
 * ── WHAT A GREEN RUN DOES NOT PROVE ───────────────────────────────────
 *
 * Nothing about the wire: purpose 0x08 has no T3 verb, no encoder and no
 * decoder, and neither function under test is called from any handler,
 * tick or commit path. Nothing about when the view counter may move
 * either — this slice deliberately changes no writer of w->current_view.
 * And the f+1 argument itself rests on the correctness of the tally path
 * these statements certify; that path is NOT exercised here.
 *
 * @file test_view_proof.c
 */

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "witness/nodus_witness_committee.h"
#include "protocol/nodus_tier3.h"
#include "server/nodus_server.h"
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"
#include "dnac/dnac.h"
#include "dnac/ledger_ids.h"
#include "nodus/nodus_types.h"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name) do { printf("  %-64s", name); } while (0)
#define PASS()     do { printf("PASS\n"); g_passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); g_failed++; } while (0)

/* ── The layout under test ────────────────────────────────────────────
 *
 *   [0..7]      "viewok\0\0"        8 bytes: 6 ASCII + 2 NUL pad
 *   [8..39]     chain_id            32 bytes
 *   [40..47]    height              uint64 big-endian
 *   [48..51]    view                uint32 big-endian
 *   [52..115]   committee_set_hash  64 bytes
 *   [116..147]  voter_id            32 bytes
 */
#define VOK_LEN 148

/* Build the VIEW_OK preimage INDEPENDENTLY of production.
 *
 * A deliberate SECOND implementation, not a call into the code under
 * test: compute_view_ok_preimage is static to nodus_witness_bft.c, and
 * even if it were not, checking production against itself would assert
 * nothing at all. §C is what ties this builder to the real one. */
static void vp_build_preimage(uint8_t out[VOK_LEN],
                               const uint8_t *chain_id,
                               uint64_t height, uint32_t view,
                               const uint8_t *set_hash,
                               const uint8_t *voter_id) {
    memcpy(out, "viewok", 6);
    out[6] = 0x00;
    out[7] = 0x00;
    memcpy(out + 8, chain_id, 32);
    for (int i = 0; i < 8; i++)
        out[40 + i] = (uint8_t)(height >> ((7 - i) * 8));
    out[48] = (uint8_t)(view >> 24);
    out[49] = (uint8_t)(view >> 16);
    out[50] = (uint8_t)(view >> 8);
    out[51] = (uint8_t)view;
    memcpy(out + 52, set_hash, 64);
    memcpy(out + 116, voter_id, NODUS_T3_WITNESS_ID_LEN);
}

/* The "DNA.CCSET.v1" set hash, rebuilt INDEPENDENTLY from the layout the
 * derivation documents: tag(16) ‖ count u16 BE ‖ count × SHA3-512(pk)[64],
 * over the pubkeys in COMMITTEE ORDER. Same reasoning as the preimage
 * builder — production must be measured against something, not itself. */
static int vp_build_set_hash(const uint8_t (*pubkeys)[DNAC_PUBKEY_SIZE],
                              int count, uint8_t out64[64]) {
    static const uint8_t tag[16] = {
        'D','N','A','.','C','C','S','E','T','.','v','1', 0, 0, 0, 0
    };
    size_t len = 16 + 2 + (size_t)count * 64;
    uint8_t *pre = malloc(len);
    if (!pre) return -1;
    size_t off = 0;
    memcpy(pre + off, tag, 16); off += 16;
    pre[off++] = (uint8_t)(((uint32_t)count) >> 8);
    pre[off++] = (uint8_t)count;
    for (int i = 0; i < count; i++) {
        if (qgp_sha3_512(pubkeys[i], DNAC_PUBKEY_SIZE, pre + off) != 0) {
            free(pre);
            return -1;
        }
        off += 64;
    }
    int rc = qgp_sha3_512(pre, off, out64);
    free(pre);
    return rc == 0 ? 0 : -1;
}

/* ── Keys ─────────────────────────────────────────────────────────────
 *
 * NINE keys, of which only the first SEVEN are ever seated in a
 * committee. Two authorities that give DIFFERENT answers is a
 * precondition for §D/§E to mean anything — see vacuity path 4 in the
 * file header. */
#define VP_N_KEYS       9
#define VP_COMMITTEE_N  7

typedef struct {
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];   /* SHA3-512(pk)[0..31] */
} vp_peer_t;

static vp_peer_t g_peers[VP_N_KEYS];

/* Deterministic keys — no RNG anywhere in this file, so a failure
 * reproduces byte-for-byte. Same derivation the verifier uses to resolve
 * a signer: witness_id = SHA3-512(pubkey)[0..31]. */
static int vp_make_keys(void) {
    for (int i = 0; i < VP_N_KEYS; i++) {
        uint8_t seed[32];
        memset(seed, (uint8_t)(0x70 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_peers[i].pk, g_peers[i].sk, seed) != 0)
            return -1;
        uint8_t full[64];
        if (qgp_sha3_512(g_peers[i].pk, QGP_DSA87_PUBLICKEYBYTES, full) != 0)
            return -1;
        memcpy(g_peers[i].id, full, NODUS_T3_WITNESS_ID_LEN);
    }
    return 0;
}

/* ── Fixture ──────────────────────────────────────────────────────── */

static void vp_rmrf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *e;
            while ((e = readdir(d)) != NULL) {
                if (strcmp(e->d_name, ".") == 0 ||
                    strcmp(e->d_name, "..") == 0) continue;
                char child[4096];
                snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
                vp_rmrf(child);
            }
            closedir(d);
        }
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

/* Prime the legacy committee resolver's per-epoch cache with the members
 * at `idx[0..n)`. nodus_committee_get_for_block answers from this cache
 * before it touches the database (nodus_witness_committee.c, the cache-hit
 * branch), and load_committee_at_height_alloc — the resolver BOTH
 * functions under test call — goes through exactly that accessor. So this
 * makes the governing committee a deterministic, DB-free input whose
 * ORDER the test controls, which matters because the set hash commits
 * seat positions.
 *
 * Parametric in DNAC_EPOCH_LENGTH, and re-callable: a leg that verifies at
 * a DIFFERENT height re-primes for that height's epoch, so no assertion
 * ever depends on two heights happening to share an epoch. Copied from
 * prime_committee in test_precommit_cert_verify_lazy.c. */
static void vp_prime(nodus_witness_t *w, uint64_t height,
                      const int *idx, int n) {
    uint64_t e = (uint64_t)DNAC_EPOCH_LENGTH;
    w->cached_committee_epoch_start = (height / e) * e;
    w->cached_committee_count = n;
    for (int i = 0; i < n; i++) {
        memcpy(w->cached_committee_pubkeys[i], g_peers[idx[i]].pk,
               DNAC_PUBKEY_SIZE);
        w->cached_committee_stakes[i]         = 1000000ULL + (uint64_t)i;
        w->cached_committee_self_stakes[i]    = 1000000000000000ULL;
        w->cached_committee_commission_bps[i] = 100;
    }
}

/* The identity order the fixtures prime: peers 0..6. */
static const int VP_COMMITTEE_IDX[VP_COMMITTEE_N] = { 0, 1, 2, 3, 4, 5, 6 };

/* A witness holding a REAL chain database.
 *
 * ⚠ A DB-LESS FIXTURE CANNOT BE USED. With no `w->db` and a non-zero
 * chain_id, load_committee_at_height returns -1 (the "holds a chain,
 * cannot read it" row), and BOTH functions under test fail closed before
 * they look at any signature — every leg below would then pass vacuously,
 * the verifier answering -2 to everything.
 *
 * The roster is seated with ALL NINE keys on purpose: it must DISAGREE
 * with the committee, so that a verdict computed from the roster is
 * visibly different from one computed from the committee (roster 9 →
 * quorum 7 → threshold 4; committee 7 → quorum 5 → threshold 3). */
static nodus_witness_t *vp_fixture(const char *dir, const uint8_t cid16[16],
                                    uint64_t height) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) { free(w); return NULL; }

    memcpy(srv->identity.pk.bytes, g_peers[0].pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, g_peers[0].sk, NODUS_SK_BYTES);
    w->server = srv;
    memcpy(w->my_id, g_peers[0].id, NODUS_T3_WITNESS_ID_LEN);

    for (int i = 0; i < VP_N_KEYS; i++) {
        uint32_t s = w->roster.n_witnesses++;
        memcpy(w->roster.witnesses[s].witness_id, g_peers[i].id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(w->roster.witnesses[s].pubkey, g_peers[i].pk, NODUS_PK_BYTES);
        w->roster.witnesses[s].active = true;
    }

    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    if (nodus_witness_create_chain_db(w, cid16) != 0 || !w->db) {
        free(srv); free(w);
        return NULL;
    }

    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);
    vp_prime(w, height, VP_COMMITTEE_IDX, VP_COMMITTEE_N);
    return w;
}

static void vp_fixture_free(nodus_witness_t *w, const char *dir) {
    if (w) {
        if (w->db) { sqlite3_close(w->db); w->db = NULL; }
        free(w->server);
        free(w);
    }
    vp_rmrf(dir);
}

/* Make the fixture SIGN AS peer `idx`, through the production producer.
 *
 * sign_view_ok reads the signer identity from `w` (my_id + the server
 * secret key) and never takes it as an argument — deliberately, so a
 * statement cannot be minted for another signer. Swapping the identity in
 * and back is therefore the only way one fixture can stand in for several
 * nodes, and it exercises the REAL producer for every voter rather than a
 * test-side re-implementation. */
static int vp_sign_as(nodus_witness_t *w, int idx,
                       uint64_t height, uint32_t view,
                       uint8_t set_hash_out[64], nodus_sig_t *sig_out) {
    uint8_t saved_id[NODUS_T3_WITNESS_ID_LEN];
    uint8_t saved_sk[NODUS_SK_BYTES];
    uint8_t saved_pk[NODUS_PK_BYTES];
    memcpy(saved_id, w->my_id, sizeof(saved_id));
    memcpy(saved_sk, w->server->identity.sk.bytes, sizeof(saved_sk));
    memcpy(saved_pk, w->server->identity.pk.bytes, sizeof(saved_pk));

    memcpy(w->my_id, g_peers[idx].id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(w->server->identity.sk.bytes, g_peers[idx].sk, NODUS_SK_BYTES);
    memcpy(w->server->identity.pk.bytes, g_peers[idx].pk, NODUS_PK_BYTES);

    int rc = nodus_witness_bft_sign_view_ok(w, height, view,
                                             set_hash_out, sig_out);

    memcpy(w->my_id, saved_id, sizeof(saved_id));
    memcpy(w->server->identity.sk.bytes, saved_sk, sizeof(saved_sk));
    memcpy(w->server->identity.pk.bytes, saved_pk, sizeof(saved_pk));
    return rc;
}

/* Peer `idx`'s public key as the typed value the verify wrappers take.
 * A cast from the raw array would rely on layout coincidence; a copy
 * cannot be wrong. */
static nodus_pubkey_t vp_pk(int idx) {
    nodus_pubkey_t pk;
    memcpy(pk.bytes, g_peers[idx].pk, NODUS_PK_BYTES);
    return pk;
}

/* Fill one proof entry from peer `idx`, signing through production. */
static int vp_entry(nodus_witness_t *w, nodus_t3_cert_entry_t *out, int idx,
                     uint64_t height, uint32_t view, uint8_t set_hash[64]) {
    nodus_sig_t sig;
    memset(out, 0, sizeof(*out));
    if (vp_sign_as(w, idx, height, view, set_hash, &sig) != 0) return -1;
    memcpy(out->voter_id, g_peers[idx].id, NODUS_T3_WITNESS_ID_LEN);
    memcpy(out->signature, sig.bytes, NODUS_SIG_BYTES);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * §B — the 148-byte layout, written out in full
 * ══════════════════════════════════════════════════════════════════════ */

/* The KAT uses SYNTHETIC field values on purpose. The real set_hash and
 * voter_id are key-derived, so no literal for them could be written
 * without running the code they come from — which would make the KAT a
 * transcript of production rather than an independent statement about the
 * layout. §C measures the real values instead. */
static void test_preimage_kat(void) {
    TEST("§B VIEW_OK preimage KAT — 148 bytes, byte for byte");

    uint8_t chain_id[32];
    for (int i = 0; i < 16; i++) chain_id[i] = 0xE9;
    for (int i = 16; i < 32; i++) chain_id[i] = 0x00;
    uint8_t set_hash[64];  memset(set_hash, 0x66, sizeof(set_hash));
    uint8_t voter_id[32];  memset(voter_id, 0x99, sizeof(voter_id));

    static const uint8_t expect[VOK_LEN] = {
        /* [0..7] "viewok" — 6 ASCII bytes then TWO explicit NUL pad */
        0x76, 0x69, 0x65, 0x77, 0x6F, 0x6B, 0x00, 0x00,
        /* [8..39] chain_id: 16 significant bytes then the 16-byte pad */
        0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9,
        0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* [40..47] height 0x0102030405060708, BIG-endian */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        /* [48..51] view 0x0A0B0C0D, BIG-endian */
        0x0A, 0x0B, 0x0C, 0x0D,
        /* [52..115] committee_set_hash, 64 bytes */
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        /* [116..147] voter_id, 32 bytes */
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
        0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
    };

    uint8_t got[VOK_LEN];
    vp_build_preimage(got, chain_id, 0x0102030405060708ull, 0x0A0B0C0Du,
                       set_hash, voter_id);

    for (int i = 0; i < VOK_LEN; i++) {
        if (got[i] != expect[i]) {
            char msg[128];
            snprintf(msg, sizeof(msg), "offset %d: got 0x%02X want 0x%02X",
                     i, got[i], expect[i]);
            FAIL(msg);
            return;
        }
    }

    /* Anti-vacuity for the tag: "viewok" is 6 chars, so BOTH byte 6 and
     * byte 7 are pad and byte 8 already belongs to chain_id. A builder
     * that leaned on a string literal's single terminator would leave
     * byte 7 undefined and this would catch it. */
    if (expect[5] != 0x6B) { FAIL("byte 5 must be 'k'"); return; }
    if (expect[6] != 0x00) { FAIL("byte 6 must be the first pad byte"); return; }
    if (expect[7] != 0x00) { FAIL("byte 7 must be the second pad byte"); return; }
    if (expect[8] == 0x00) { FAIL("byte 8 is chain_id, not a NUL"); return; }
    PASS();
}

/* ══════════════════════════════════════════════════════════════════════
 * The main fixture-driven body: §0 controls, §C binding, §D substitution,
 * §E threshold, §F fault-vs-verdict, §G purity.
 * ══════════════════════════════════════════════════════════════════════ */

static void test_view_proof_body(void) {
    TEST("§0/§C-§G VIEW_OK production binding, thresholds and faults");

    char dir[] = "/tmp/test_view_proof_XXXXXX";
    if (mkdtemp(dir) == NULL) { FAIL("temp dir"); return; }

    uint8_t cid16[16];
    memset(cid16, 0x5E, sizeof(cid16));

    const uint64_t H  = 5;      /* the height the statements are about   */
    const uint64_t H2 = 6;      /* a different height, re-primed below   */
    const uint32_t V  = 3;      /* the view they certify                 */

    nodus_witness_t *w = vp_fixture(dir, cid16, H);

#define BAIL(msg) do { vp_fixture_free(w, dir); FAIL(msg); return; } while (0)

    if (!w) BAIL("fixture");

    /* ── §0 — THE ANTI-VACUITY CONTROLS ────────────────────────────────
     * Every one of these closes a path on which the legs below would pass
     * while measuring nothing. They come FIRST, before any signature is
     * offered to anything. */

    /* (a) The committee really resolves, is non-empty, and has the size
     *     AND the seat order this file assumes. Order is not cosmetic: it
     *     is inside the set hash. Read through the PUBLIC accessor, which
     *     is the same one the code under test reaches via
     *     load_committee_at_height_alloc. */
    {
        nodus_committee_member_t *cm =
            calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*cm));
        if (!cm) BAIL("committee scratch alloc");
        int n = 0;
        if (nodus_committee_get_for_block(w, H, cm,
                                           DNAC_MAX_ACTIVE_VALIDATORS,
                                           &n) != 0) {
            free(cm);
            BAIL("§0 the committee at H must RESOLVE — with a fault the "
                 "verifier answers -2 to everything and nothing is measured");
        }
        if (n != VP_COMMITTEE_N) {
            free(cm);
            BAIL("§0 the committee at H must have exactly 7 members — an "
                 "empty or differently-sized set makes every leg vacuous");
        }
        for (int i = 0; i < n; i++) {
            if (memcmp(cm[i].pubkey, g_peers[VP_COMMITTEE_IDX[i]].pk,
                       DNAC_PUBKEY_SIZE) != 0) {
                free(cm);
                BAIL("§0 the committee must resolve in the SEAT ORDER the "
                     "fixture primed — order is committed by the set hash");
            }
        }
        free(cm);
    }

    /* (b) The threshold is the committee's f+1 = 3, and 3 is NOT the
     *     anti-amplification floor of 2 — so the leg "f valid signatures
     *     do not verify" is testing the formula, not the floor. */
    if (dna_bft_quorum(VP_COMMITTEE_N) != 5)
        BAIL("§0 dna_bft_quorum(7) must be 5");
    {
        uint32_t q = dna_bft_quorum(VP_COMMITTEE_N);
        uint32_t f1 = ((q - 1) / 2) + 1;
        /* 3, and the anti-amplification floor is 2 — so the value under
         * test comes from the DERIVATION, not from the floor. A committee
         * small enough to be floored would make the "f valid statements
         * are not enough" leg pass for the wrong reason. */
        if (f1 != 3)
            BAIL("§0 the committee's f+1 must be 3, above the floor of 2 — "
                 "otherwise §E measures the floor, not the derivation");
    }

    /* (c) The roster and the committee DISAGREE, so §D/§E can tell which
     *     authority the code consulted. bft_config comes from the roster
     *     of 9 (quorum 7, giving a threshold of 4); the committee of 7
     *     gives 3. A verifier that read bft_config would demand 4 and the
     *     three-signature leg below would go red. */
    if (w->roster.n_witnesses != VP_N_KEYS)
        BAIL("§0 the roster must seat 9");
    if (w->bft_config.quorum == 0)
        BAIL("§0 quorum 0 — bft_config_init took its consensus-disabled "
             "branch and nothing below is being measured");
    if (w->bft_config.quorum != 7)
        BAIL("§0 the roster quorum must be (2*9)/3+1 = 7");
    if (((w->bft_config.quorum - 1) / 2) + 1 ==
        ((dna_bft_quorum(VP_COMMITTEE_N) - 1) / 2) + 1)
        BAIL("§0 the roster-derived and committee-derived thresholds must "
             "DIFFER, or §E cannot tell which one the verifier used");

    /* ── §G — THE PRODUCER IS PURE ──────────────────────────────────── */
    w->current_view        = 42;
    w->view_change_target  = 0;
    w->view_change_count   = 0;
    w->view_change_in_progress = false;

    uint8_t set_hash[64];
    nodus_sig_t sig0;
    if (nodus_witness_bft_sign_view_ok(w, H, V, set_hash, &sig0) != 0)
        BAIL("§C sign_view_ok must succeed with a resolvable committee");

    if (w->current_view != 42)
        BAIL("§G signing moved w->current_view — the producer must touch "
             "no round state");
    if (w->view_change_target != 0 || w->view_change_count != 0 ||
        w->view_change_in_progress)
        BAIL("§G signing touched view-change state — the producer must be "
             "pure");

    /* ── §C — PRODUCTION BUILDS THE BYTES §B PINNED ─────────────────── */

    /* (c1) The set hash production signed under IS the "DNA.CCSET.v1"
     *      derivation over the committee pubkeys in seat order — rebuilt
     *      here from the documented layout, not read back from the code
     *      that produced it. */
    {
        uint8_t (*pks)[DNAC_PUBKEY_SIZE] =
            calloc((size_t)VP_COMMITTEE_N, DNAC_PUBKEY_SIZE);
        if (!pks) BAIL("set-hash scratch alloc");
        for (int i = 0; i < VP_COMMITTEE_N; i++)
            memcpy(pks[i], g_peers[VP_COMMITTEE_IDX[i]].pk, DNAC_PUBKEY_SIZE);
        uint8_t expect_sh[64];
        int rc = vp_build_set_hash((const uint8_t (*)[DNAC_PUBKEY_SIZE])pks,
                                    VP_COMMITTEE_N, expect_sh);
        free(pks);
        if (rc != 0) BAIL("independent set-hash rebuild");
        if (memcmp(expect_sh, set_hash, 64) != 0)
            BAIL("§C the set hash production signed under is not the "
                 "DNA.CCSET.v1 derivation over the seated committee");
        /* And it is not a degenerate value. A zero or all-same hash would
         * satisfy the comparison above only if BOTH sides were broken,
         * but an emitted zero is the specific failure the producer
         * promises never to make. */
        uint8_t zero[64] = {0};
        if (memcmp(set_hash, zero, 64) == 0)
            BAIL("§C the set hash must never be zero");
    }

    /* (c2) The 148 bytes production signed are byte-identical to this
     *      file's independently built ones. If the two layouts had
     *      drifted by a single byte, this signature would not verify —
     *      which is what makes §B a statement about the shipped code. */
    {
        uint8_t pre[VOK_LEN];
        vp_build_preimage(pre, w->chain_id, H, V, set_hash, g_peers[0].id);
        nodus_pubkey_t pk0 = vp_pk(0);
        if (nodus_verify_view_ok(&sig0, pre, sizeof(pre), &pk0) != 0)
            BAIL("§C production signed different bytes than §B's layout");
    }

    /* ── §E — the POSITIVE control, then the threshold ──────────────── */

    nodus_t3_cert_entry_t proof[VP_COMMITTEE_N];
    uint8_t sh_i[64];
    for (int i = 0; i < VP_COMMITTEE_N; i++) {
        if (vp_entry(w, &proof[i], i, H, V, sh_i) != 0)
            BAIL("§E signing a committee member's statement");
        if (memcmp(sh_i, set_hash, 64) != 0)
            BAIL("§E every signer must resolve the SAME set hash");
    }

    /* THE POSITIVE CONTROL. Before any refusal is asserted: a correct
     * proof VERIFIES. Without this, a verifier that refuses everything
     * would pass every negative leg below. */
    if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof,
                                             VP_COMMITTEE_N) != 0)
        BAIL("§E a full, correct proof must verify (positive control)");

    /* Exactly f+1 = 3 distinct valid statements verify... */
    if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof, 3) != 0)
        BAIL("§E exactly f+1 = 3 distinct valid statements must verify");

    /* ...and f = 2 do NOT. -1 is a VERDICT: the input was well formed and
     * fully judged, there were simply not enough distinct signers. */
    if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof, 2) != -1)
        BAIL("§E f = 2 statements must be REJECTED with -1, not accepted "
             "and not reported as a local fault");
    if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof, 1) != -1)
        BAIL("§E one statement must be rejected with -1");

    /* THE DEDUP. The same statement repeated f+1 times is still ONE
     * signer. Without this, any single member could manufacture view
     * authority by copying its own statement. */
    {
        nodus_t3_cert_entry_t dup[3];
        for (int i = 0; i < 3; i++) dup[i] = proof[0];
        if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, dup, 3) != -1)
            BAIL("§E one statement repeated 3 times must NOT verify — "
                 "duplicate voter_ids count once");
    }

    /* A NON-MEMBER buys nothing. Peer 7 is in the transport ROSTER but
     * not in the committee at H, so its statement must neither count
     * toward the threshold nor void the proof it is attached to. */
    {
        nodus_t3_cert_entry_t mixed[3];
        mixed[0] = proof[0];
        mixed[1] = proof[1];
        uint8_t sh_out[64];
        if (vp_entry(w, &mixed[2], 7, H, V, sh_out) != 0)
            BAIL("§E signing the non-member's statement");
        /* It is a REAL, verifiable signature over the REAL set hash — the
         * only thing wrong with it is who signed it. */
        if (memcmp(sh_out, set_hash, 64) != 0)
            BAIL("§E the non-member must sign over the same set hash, or "
                 "this leg is about the hash and not about membership");
        if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, mixed, 3) != -1)
            BAIL("§E a non-member's statement must not complete a proof "
                 "that has only 2 genuine members");
        /* Skipped, NOT fatal: appending it to a sufficient proof must not
         * void that proof, or one junk entry would be a denial of
         * service against every sound statement. */
        nodus_t3_cert_entry_t padded[4];
        padded[0] = proof[0];
        padded[1] = proof[1];
        padded[2] = proof[2];
        padded[3] = mixed[2];
        if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, padded, 4) != 0)
            BAIL("§E a non-member entry must be SKIPPED, not fatal — a "
                 "sound proof must survive one junk entry");
    }

    /* ── §D — the substitution matrix ───────────────────────────────── */

    /* (d1) WRONG VIEW. The same statements must not prove another view. */
    if (nodus_witness_bft_verify_view_proof(w, H, V + 1, set_hash, proof,
                                             VP_COMMITTEE_N) != -1)
        BAIL("§D view: statements for view V must not prove view V+1");

    /* (d2) WRONG HEIGHT. Re-prime the cache for H2's epoch with the SAME
     *      members first, so the committee resolves identically there and
     *      the ONLY thing that differs is the height in the preimage.
     *      Without the re-prime a short-epoch build could take the
     *      set-mismatch path and this leg would silently measure cache
     *      scope instead of the height binding. */
    vp_prime(w, H2, VP_COMMITTEE_IDX, VP_COMMITTEE_N);
    {
        /* Proof that the re-prime really produced the same authority:
         * a fresh signature at H2 must carry the SAME set hash. */
        uint8_t sh_h2[64];
        nodus_sig_t tmp;
        if (nodus_witness_bft_sign_view_ok(w, H2, V, sh_h2, &tmp) != 0)
            BAIL("§D sign at H2");
        if (memcmp(sh_h2, set_hash, 64) != 0)
            BAIL("§D the re-primed committee at H2 must be the SAME set, "
                 "or the height leg is measuring the committee and not "
                 "the height");
    }
    if (nodus_witness_bft_verify_view_proof(w, H2, V, set_hash, proof,
                                             VP_COMMITTEE_N) != -1)
        BAIL("§D height: statements signed at H must not prove view V at "
             "H2 — and it must be -1, a verdict, not -2");
    vp_prime(w, H, VP_COMMITTEE_IDX, VP_COMMITTEE_N);   /* restore */

    /* (d3) WRONG VOTER_ID. Re-label one member's signature under another
     *      member's id. Both are genuine committee members, so this is a
     *      pure test of the voter_id binding in the preimage: the
     *      re-labelled entry must stop counting, dropping a 3-signature
     *      proof to 2. */
    {
        nodus_t3_cert_entry_t relabelled[3];
        relabelled[0] = proof[0];
        relabelled[1] = proof[1];
        relabelled[2] = proof[2];
        memcpy(relabelled[2].voter_id, g_peers[3].id,
               NODUS_T3_WITNESS_ID_LEN);
        if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash,
                                                 relabelled, 3) != -1)
            BAIL("§D voter_id: a statement re-labelled under another "
                 "member's id must stop counting");
    }

    /* (d4) WRONG SET HASH — and the FAULT/VERDICT distinction (§F).
     *      A carried hash this node did not resolve means "I cannot
     *      judge", which is -2, NOT -1. The two are asserted with
     *      DIFFERENT expected values a line apart, so a build that
     *      conflated them would go red here even though both are
     *      non-zero. */
    {
        uint8_t bad_sh[64];
        memcpy(bad_sh, set_hash, 64);
        bad_sh[0] ^= 0x01;
        if (nodus_witness_bft_verify_view_proof(w, H, V, bad_sh, proof,
                                                 VP_COMMITTEE_N) != -2)
            BAIL("§F a set hash this node did not resolve must be -2 (I "
                 "cannot judge), never -1 (this proof is invalid)");
    }

    /* (d5) The REALISTIC form of the same fault: this node resolves a
     *      genuinely DIFFERENT committee for that height — one member
     *      swapped — and must decline to judge rather than denounce
     *      statements the rest of the cluster considers sound. */
    {
        static const int drifted[VP_COMMITTEE_N] = { 0, 1, 2, 3, 4, 5, 7 };
        vp_prime(w, H, drifted, VP_COMMITTEE_N);
        if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof,
                                                 VP_COMMITTEE_N) != -2)
            BAIL("§F resolving a different committee must be -2, not a "
                 "verdict against the peers");
        /* SEAT ORDER alone is enough to make it a different set — the
         * hash commits positions, not just membership. */
        static const int reordered[VP_COMMITTEE_N] = { 1, 0, 2, 3, 4, 5, 6 };
        vp_prime(w, H, reordered, VP_COMMITTEE_N);
        if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof,
                                                 VP_COMMITTEE_N) != -2)
            BAIL("§F the same members in a different SEAT ORDER must be a "
                 "different set — the hash commits positions");
        vp_prime(w, H, VP_COMMITTEE_IDX, VP_COMMITTEE_N);   /* restore */
        /* Restoration control: the proof verifies again, so the two -2s
         * above were about the committee and not about a fixture the
         * legs left broken. */
        if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof,
                                                 VP_COMMITTEE_N) != 0)
            BAIL("§F restoring the committee must restore the verdict");
    }

    /* (d6) WRONG CHAIN. chain_id is read from the witness, never passed,
     *      so the only way to vary it is to hand the verifier a statement
     *      signed under a different chain identity. Signing one requires
     *      no second database: the test builds the preimage itself with a
     *      foreign chain_id and signs it through the production wrapper,
     *      which is exactly what a node on the other chain would emit. */
    {
        uint8_t foreign_chain[32];
        memcpy(foreign_chain, w->chain_id, 32);
        foreign_chain[0] ^= 0xFF;

        nodus_t3_cert_entry_t foreign[3];
        memset(foreign, 0, sizeof(foreign));
        for (int i = 0; i < 3; i++) {
            uint8_t pre[VOK_LEN];
            vp_build_preimage(pre, foreign_chain, H, V, set_hash,
                               g_peers[i].id);
            nodus_sig_t s;
            nodus_seckey_t sk;
            memcpy(sk.bytes, g_peers[i].sk, NODUS_SK_BYTES);
            if (nodus_sign_view_ok(&s, pre, sizeof(pre), &sk) != 0)
                BAIL("§D signing under the foreign chain");
            memcpy(foreign[i].voter_id, g_peers[i].id,
                   NODUS_T3_WITNESS_ID_LEN);
            memcpy(foreign[i].signature, s.bytes, NODUS_SIG_BYTES);
        }
        /* Anti-vacuity: those signatures ARE valid — against the foreign
         * chain's bytes. So the refusal below is about the chain binding,
         * not about a broken signature. */
        {
            uint8_t pre[VOK_LEN];
            vp_build_preimage(pre, foreign_chain, H, V, set_hash,
                               g_peers[0].id);
            nodus_sig_t s;
            memcpy(s.bytes, foreign[0].signature, NODUS_SIG_BYTES);
            nodus_pubkey_t pk0 = vp_pk(0);
            if (nodus_verify_view_ok(&s, pre, sizeof(pre), &pk0) != 0)
                BAIL("§D the foreign-chain signatures must themselves be "
                     "valid, or the refusal proves nothing");
        }
        if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, foreign,
                                                 3) != -1)
            BAIL("§D chain_id: statements from another chain must not "
                 "prove a view on this one — the post-wipe replay");
    }

    /* (d7) An over-long bundle is refused UP FRONT, as the wire bound
     *      demands. n_entries above NODUS_T3_MAX_WITNESSES is malformed
     *      input, i.e. a verdict.
     *
     *      ⚠ The declared count deliberately exceeds `proof`'s real
     *      length. That is safe ONLY because the bound is checked before
     *      any entry is touched — the same up-front position
     *      verify_prepared_cert uses. If a future edit moved that check
     *      below the loop, this line would read past the array and the
     *      sanitizer would say so loudly, which is the intended alarm:
     *      the bound belongs first. */
    if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof,
                                             NODUS_T3_MAX_WITNESSES + 1) != -1)
        BAIL("§E more entries than the wire allows must be refused");
    if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof, 0) != -1)
        BAIL("§E an empty bundle must be refused");
    if (nodus_witness_bft_verify_view_proof(w, H, V, NULL, proof, 3) != -1)
        BAIL("§E a NULL set hash must be refused");

    /* Final control: after every negative leg, the correct proof still
     * verifies. A fixture the legs quietly broke would fail here. */
    if (nodus_witness_bft_verify_view_proof(w, H, V, set_hash, proof,
                                             VP_COMMITTEE_N) != 0)
        BAIL("§0 the correct proof must still verify at the end");

#undef BAIL

    vp_fixture_free(w, dir);
    PASS();
}

/* ══════════════════════════════════════════════════════════════════════
 * §H — the pre-genesis answer: no committee is a FAULT, not an empty set
 * ══════════════════════════════════════════════════════════════════════ */

/* A witness whose chain database is real but whose validator table is
 * EMPTY — the committed (rc 0, count 0) answer. verify_prepared_cert
 * treats that as the documented gossip-roster bootstrap; VIEW_OK still
 * refuses to SIGN, because a set hash over an empty set is not a
 * statement about anything.
 *
 * But the producer answers 1, not -1: a committed "there is nobody to
 * certify against here", which the caller answers by taking the
 * pre-genesis BOOTSTRAP path. Reporting it as a fault locked a fresh
 * chain out of ever rotating once the verified proof became the only
 * writer of current_view — see the full note at the assertion. The
 * verifier still declines to judge (-2): there is no set to measure a
 * carried proof against. */
static void test_pre_genesis_refusal(void) {
    TEST("§H no committee at that height — producer 1 (bootstrap), verifier -2");

    char dir[] = "/tmp/test_view_proof_pg_XXXXXX";
    if (mkdtemp(dir) == NULL) { FAIL("temp dir"); return; }

    uint8_t cid16[16];
    memset(cid16, 0x7C, sizeof(cid16));

    nodus_witness_t *w = vp_fixture(dir, cid16, 5);

#define PG_BAIL(msg) do { vp_fixture_free(w, dir); FAIL(msg); return; } while (0)

    if (!w) PG_BAIL("fixture");

    /* Drop the primed cache back to the sentinel so the lookup takes the
     * MISS path against the empty validator table — the count-0 answer
     * must come from a real read, not from a hand-set cache. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;

    /* Anti-vacuity: the lookup must SUCCEED with count 0. If it faulted
     * instead, both assertions below would hold for the wrong reason. */
    {
        nodus_committee_member_t *cm =
            calloc((size_t)DNAC_MAX_ACTIVE_VALIDATORS, sizeof(*cm));
        if (!cm) PG_BAIL("committee scratch alloc");
        int n = -1;
        int rc = nodus_committee_get_for_block(w, 5, cm,
                                                DNAC_MAX_ACTIVE_VALIDATORS,
                                                &n);
        free(cm);
        if (rc != 0)
            PG_BAIL("§H the empty-table lookup must SUCCEED with count 0, "
                    "not fault — otherwise this section tests the fault "
                    "path it does not mean to");
        if (n != 0)
            PG_BAIL("§H the validator table must be empty here");
    }

    uint8_t set_hash[64];
    nodus_sig_t sig;
    /* ⚠ 1, NOT -1 — AND THE DIFFERENCE IS THE WHOLE POINT.
     *
     * The producer still refuses to SIGN: a set hash over an empty set is
     * not a statement about anything, and this must never become a
     * signature. What changed in Faz 2C2 is the CLASS of the answer. A
     * bare -1 said "fault", and once the verified proof became the only
     * writer of current_view that turned into a LOCK: no committee exists
     * until the genesis block commits, so no node could sign, so no proof
     * could exist, so a fresh cluster whose genesis round landed on a
     * silent leader could never rotate away from it and the chain would
     * never start. Two shipped tests said so out loud (test_bft_liveness,
     * test_witness_newview_convergence) and the Genesis Protocol harness
     * builds exactly that state on every run.
     *
     * 1 is the committed answer "there is nobody to certify against at
     * this height", and the caller answers it by taking the pre-genesis
     * BOOTSTRAP path — moving on its own observed quorum, on the same
     * gossip-roster authority this tree already documents for leader
     * election and prepared-cert voter resolution in this same window.
     * The window closes the instant genesis seats a committee.
     *
     * A -1 here would therefore be a regression to a chain that cannot
     * start, which is why this asserts the exact value and not "non-zero". */
    int prc = nodus_witness_bft_sign_view_ok(w, 5, 1, set_hash, &sig);
    if (prc != 1)
        PG_BAIL("§H pre-genesis the producer must answer 1 (no committee to "
                "certify against — take the bootstrap path), never -1 (a "
                "fault), which would lock a fresh chain out of ever rotating");

    /* And the verifier declines rather than convicting. The entries are
     * structurally fine; there is simply no authority to judge them by. */
    {
        nodus_t3_cert_entry_t e[3];
        memset(e, 0, sizeof(e));
        for (int i = 0; i < 3; i++)
            memcpy(e[i].voter_id, g_peers[i].id, NODUS_T3_WITNESS_ID_LEN);
        uint8_t any_sh[64];
        memset(any_sh, 0x11, sizeof(any_sh));
        if (nodus_witness_bft_verify_view_proof(w, 5, 1, any_sh, e, 3) != -2)
            PG_BAIL("§H with no committee the verifier must answer -2 (I "
                    "cannot decide), never -1");
    }

#undef PG_BAIL

    vp_fixture_free(w, dir);
    PASS();
}

int main(void) {
    printf("Nodus O15N Faz 2B — VIEW_OK view-authority primitives\n");
    printf("=====================================================\n");

    if (vp_make_keys() != 0) {
        fprintf(stderr, "FATAL: deterministic keypair derivation failed\n");
        return 1;
    }

    test_preimage_kat();
    test_view_proof_body();
    test_pre_genesis_refusal();

    printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed ? 1 : 0;
}
