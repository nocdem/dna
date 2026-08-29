/**
 * Nodus — Domain Separation Sign/Verify Tests (C2 fix + O15N Faz 2A)
 *
 * Verifies that signatures produced under one purpose byte cannot be relayed
 * against verifiers expecting a different purpose — closes the Dilithium5
 * signing oracle vulnerability at the challenge handler.
 *
 * ── O15N Faz 2A — what the later half of this file adds ───────────────
 *
 * The original C2 separation was REVERTED in practice by the v0.17.5
 * compat bridge: `nodus_sign_tagged` discarded the purpose byte (its body
 * was literally `(void)purpose;` before a RAW sign) and
 * `nodus_verify_tagged` ended in an UNCONDITIONAL raw-verify fallback.
 * That is why test_cross_domain_fails and test_every_pair_rejects are
 * still disabled in main() below — for purposes 0x01-0x05 the bypass is
 * DELIBERATELY still in place, and must stay exactly as wide as it is.
 *
 * Faz 2A makes two purposes STRICT — PREPARED (0x07) and VIEWOK (0x08),
 * both witness-to-witness on port 4004 where no shipped client can reach
 * them — and gives PREPARED a chain-bound preimage:
 *
 *   §A the strict set is exactly {0x07, 0x08} and nothing else
 *   §B the 116-byte PREPARED preimage, byte for byte (layout KAT)
 *   §C production rebuilds that same preimage (binds §B to the real code)
 *   §D substitution matrix — chain_id, view, height, tx_hash each bound
 *   §E cross-domain — 0x07 and 0x08 do not interchange
 *   §F the bypass is really lifted — a RAW signature is refused for both
 *   §G the compat bridge is EXACTLY as wide as before (0x01 still raw-OK)
 *
 * ⚠ §E and §F are not the same assertion twice. §F goes red from
 * reverting the VERIFY half alone; §E needs BOTH halves reverted. The
 * pair is what proves each half is independently load-bearing — lifting
 * only the signing half would change nothing an attacker must defeat,
 * because the verifier would still accept an untagged signature.
 *
 * ── What a green run does NOT prove ───────────────────────────────────
 *
 * Nothing about wire compatibility with a running cluster: the domain
 * change is a consensus break and rides NODUS_T3_BFT_PROTOCOL_VER
 * (4 -> 5), enforced in test_witness_protocol_version_gate. Nothing about
 * VIEWOK's message plumbing either — 0x08 has no producer on the wire
 * yet; this file pins its DOMAIN so the plumbing cannot later land on an
 * unseparated purpose.
 *
 * ── What it requires ──────────────────────────────────────────────────
 *
 * Nothing beyond a default build: no compile flags, no environment.
 * §C/§D create two witness fixtures with REAL chain databases under
 * /tmp, close both sqlite handles and remove both directories, so the
 * run leaves nothing behind.
 *
 * ── How it could lie ──────────────────────────────────────────────────
 *
 * A quorum of ZERO. With a roster below NODUS_T3_MIN_WITNESSES,
 * nodus_witness_bft_config_init takes its "below minimum — consensus
 * disabled" branch and zeroes the quorum, at which point EVERY
 * certificate verifies and §C/§D pass while measuring nothing. The
 * fixture seats 5 and the quorum is ASSERTED to be 4 before any
 * certificate is offered.
 */

#define NODUS_WITNESS_INTERNAL_API 1

#include "crypto/nodus_sign.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_platform.h"
#include "witness/nodus_witness.h"
#include "witness/nodus_witness_bft.h"
#include "protocol/nodus_tier3.h"
#include "server/nodus_server.h"
#include "nodus/nodus_types.h"

#include <dirent.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST(name) do { printf("  %-60s", name); } while(0)
#define PASS()     do { printf("PASS\n"); passed++; } while(0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while(0)

static int passed = 0;
static int failed = 0;

/* Generate a keypair into global-ish state for test reuse. */
static nodus_pubkey_t g_pk;
static nodus_seckey_t g_sk;

static int setup_keypair(void) {
    /* qgp_dsa87_keypair expects raw buffers of the right sizes. */
    return qgp_dsa87_keypair(g_pk.bytes, g_sk.bytes);
}

/* ── Positive test: sign under X, verify under X → pass ───────────── */

static void test_auth_challenge_roundtrip(void) {
    TEST("auth_challenge sign+verify roundtrip");
    uint8_t nonce[NODUS_NONCE_LEN];
    nodus_random(nonce, sizeof(nonce));

    nodus_sig_t sig;
    if (nodus_sign_auth_challenge(&sig, nonce, &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_auth_challenge(&sig, nonce, &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

static void test_kyber_bind_roundtrip(void) {
    TEST("kyber_bind sign+verify roundtrip");
    uint8_t data[1600];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_kyber_bind(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_kyber_bind(&sig, data, sizeof(data), &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

static void test_t3_envelope_roundtrip(void) {
    TEST("t3_envelope sign+verify roundtrip");
    uint8_t data[256];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_t3_envelope(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_t3_envelope(&sig, data, sizeof(data), &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

static void test_value_store_roundtrip(void) {
    TEST("value_store sign+verify roundtrip");
    uint8_t data[512];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_value_store(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_value_store(&sig, data, sizeof(data), &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

static void test_cert_roundtrip(void) {
    TEST("cert sign+verify roundtrip");
    uint8_t data[128];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_cert(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }
    if (nodus_verify_cert(&sig, data, sizeof(data), &g_pk) != 0) { FAIL("verify"); return; }
    PASS();
}

/* ── Negative: cross-domain verify must fail ──────────────────────── */

static void test_cross_domain_fails(void) {
    TEST("cross-domain verify rejects (auth_challenge → kyber_bind)");
    uint8_t nonce[NODUS_NONCE_LEN];
    nodus_random(nonce, sizeof(nonce));

    nodus_sig_t sig;
    if (nodus_sign_auth_challenge(&sig, nonce, &g_sk) != 0) { FAIL("sign"); return; }

    /* Attempt to verify as KYBER_BIND with same bytes — must fail. */
    if (nodus_verify_kyber_bind(&sig, nonce, sizeof(nonce), &g_pk) == 0) {
        FAIL("cross-domain verify accepted sig — oracle still open");
        return;
    }
    PASS();
}

static void test_every_pair_rejects(void) {
    TEST("all 5 domains pairwise cross-reject (5x5 matrix, 20 negative tests)");
    uint8_t data[128];
    nodus_random(data, sizeof(data));

    /* Produce a sig under each domain */
    nodus_sig_t sigs[5];
    if (nodus_sign_auth_challenge(&sigs[0], data, &g_sk) != 0) { FAIL("sign ac"); return; }
    if (nodus_sign_kyber_bind(&sigs[1], data, sizeof(data), &g_sk) != 0) { FAIL("sign kb"); return; }
    if (nodus_sign_t3_envelope(&sigs[2], data, sizeof(data), &g_sk) != 0) { FAIL("sign t3"); return; }
    if (nodus_sign_value_store(&sigs[3], data, sizeof(data), &g_sk) != 0) { FAIL("sign vs"); return; }
    if (nodus_sign_cert(&sigs[4], data, sizeof(data), &g_sk) != 0) { FAIL("sign ct"); return; }

    /* For each sig, matching verifier passes, all 4 non-matching verifiers fail */
    int ac_len = NODUS_NONCE_LEN;  /* AUTH_CHALLENGE expects 32B */
    int other_len = (int)sizeof(data);

    /* Matching cases (5) */
    if (nodus_verify_auth_challenge(&sigs[0], data, &g_pk) != 0) { FAIL("ac→ac should pass"); return; }
    if (nodus_verify_kyber_bind(&sigs[1], data, other_len, &g_pk) != 0) { FAIL("kb→kb"); return; }
    if (nodus_verify_t3_envelope(&sigs[2], data, other_len, &g_pk) != 0) { FAIL("t3→t3"); return; }
    if (nodus_verify_value_store(&sigs[3], data, other_len, &g_pk) != 0) { FAIL("vs→vs"); return; }
    if (nodus_verify_cert(&sigs[4], data, other_len, &g_pk) != 0) { FAIL("ct→ct"); return; }

    /* Mismatch cases (20) — every sig must fail against every non-matching verifier.
     * We use AC's 32B verify path and other domains' full-size path. When sizes differ
     * (e.g., AC=32 vs others=128) the preimage also differs so verify fails for that
     * reason too — which is fine, still demonstrates domain separation. */
    #define CHECK_REJECT(fn, s, d, dl, name) \
        do { if (fn(s, d, dl, &g_pk) == 0) { FAIL(name " unexpectedly accepted"); return; } } while(0)

    /* sigs[0] (AC sig) attempted against every other verifier */
    CHECK_REJECT(nodus_verify_kyber_bind,  &sigs[0], data, ac_len,    "ac→kb");
    CHECK_REJECT(nodus_verify_t3_envelope, &sigs[0], data, ac_len,    "ac→t3");
    CHECK_REJECT(nodus_verify_value_store, &sigs[0], data, ac_len,    "ac→vs");
    CHECK_REJECT(nodus_verify_cert,        &sigs[0], data, ac_len,    "ac→ct");
    /* sigs[1] (KB sig) */
    if (nodus_verify_auth_challenge(&sigs[1], data, &g_pk) == 0)     { FAIL("kb→ac"); return; }
    CHECK_REJECT(nodus_verify_t3_envelope, &sigs[1], data, other_len, "kb→t3");
    CHECK_REJECT(nodus_verify_value_store, &sigs[1], data, other_len, "kb→vs");
    CHECK_REJECT(nodus_verify_cert,        &sigs[1], data, other_len, "kb→ct");
    /* sigs[2] (T3 sig) */
    if (nodus_verify_auth_challenge(&sigs[2], data, &g_pk) == 0)     { FAIL("t3→ac"); return; }
    CHECK_REJECT(nodus_verify_kyber_bind,  &sigs[2], data, other_len, "t3→kb");
    CHECK_REJECT(nodus_verify_value_store, &sigs[2], data, other_len, "t3→vs");
    CHECK_REJECT(nodus_verify_cert,        &sigs[2], data, other_len, "t3→ct");
    /* sigs[3] (VS sig) */
    if (nodus_verify_auth_challenge(&sigs[3], data, &g_pk) == 0)     { FAIL("vs→ac"); return; }
    CHECK_REJECT(nodus_verify_kyber_bind,  &sigs[3], data, other_len, "vs→kb");
    CHECK_REJECT(nodus_verify_t3_envelope, &sigs[3], data, other_len, "vs→t3");
    CHECK_REJECT(nodus_verify_cert,        &sigs[3], data, other_len, "vs→ct");
    /* sigs[4] (CT sig) */
    if (nodus_verify_auth_challenge(&sigs[4], data, &g_pk) == 0)     { FAIL("ct→ac"); return; }
    CHECK_REJECT(nodus_verify_kyber_bind,  &sigs[4], data, other_len, "ct→kb");
    CHECK_REJECT(nodus_verify_t3_envelope, &sigs[4], data, other_len, "ct→t3");
    CHECK_REJECT(nodus_verify_value_store, &sigs[4], data, other_len, "ct→vs");

    #undef CHECK_REJECT
    PASS();
}

/* ── Compat: raw sig accepted by tagged verify (fallback bridge) ───── */

static void test_raw_sig_accepted_via_fallback(void) {
    TEST("raw nodus_sign sig accepted by tagged verify via compat fallback");
    uint8_t nonce[NODUS_NONCE_LEN];
    nodus_random(nonce, sizeof(nonce));

    nodus_sig_t sig;
    /* Sign RAW (pre-11467980 client path — e.g. shipped Flutter libdna) */
    if (nodus_sign(&sig, nonce, sizeof(nonce), &g_sk) != 0) { FAIL("raw sign"); return; }

    /* Tagged verify must ACCEPT this via the compat fallback in
     * nodus_verify_tagged(). Remove this case + the fallback path once
     * all deployed clients ship commit 11467980 or later. */
    if (nodus_verify_auth_challenge(&sig, nonce, &g_pk) != 0) {
        FAIL("compat fallback missing — pre-11467980 clients cannot auth");
        return;
    }
    PASS();
}

/* ── Negative: tampered preimage must fail ────────────────────────── */

static void test_tampered_data_fails(void) {
    TEST("tampered data byte fails verify");
    uint8_t data[64];
    nodus_random(data, sizeof(data));

    nodus_sig_t sig;
    if (nodus_sign_cert(&sig, data, sizeof(data), &g_sk) != 0) { FAIL("sign"); return; }

    /* Flip a bit */
    data[7] ^= 0x01;
    if (nodus_verify_cert(&sig, data, sizeof(data), &g_pk) == 0) {
        FAIL("tampered data verified — impossible"); return;
    }
    PASS();
}

/* ══════════════════════════════════════════════════════════════════════
 * O15N Faz 2A — the STRICT domains (PREPARED 0x07, VIEWOK 0x08)
 * ══════════════════════════════════════════════════════════════════════ */

/* The layout under test:
 *   [0..7]     "prepared"   8 bytes ASCII, NO NUL terminator
 *   [8..39]    chain_id     32 bytes
 *   [40..43]   view         uint32 big-endian
 *   [44..51]   height       uint64 big-endian
 *   [52..115]  tx_hash      64 bytes
 */
#define PREP_LEN 116

/* Build the PREPARED preimage INDEPENDENTLY of production.
 *
 * A deliberate second implementation, not a call into the code under
 * test: compute_prepared_preimage is static to nodus_witness_bft.c, and
 * even if it were not, checking production against itself would assert
 * nothing. §C is what ties this builder to the real one. */
static void build_prepared_preimage(uint8_t out[PREP_LEN],
                                     const uint8_t *chain_id,
                                     uint32_t view, uint64_t height,
                                     const uint8_t *tx_hash) {
    memcpy(out, "prepared", 8);          /* 8 chars, NUL not copied */
    memcpy(out + 8, chain_id, 32);
    out[40] = (uint8_t)(view >> 24);
    out[41] = (uint8_t)(view >> 16);
    out[42] = (uint8_t)(view >> 8);
    out[43] = (uint8_t)view;
    for (int i = 0; i < 8; i++)
        out[44 + i] = (uint8_t)(height >> ((7 - i) * 8));
    memcpy(out + 52, tx_hash, NODUS_T3_TX_HASH_LEN);
}

/* chain_id the fixtures hold: nodus_witness_set_chain_id copies 16 bytes
 * and ZERO-PADS to 32 (nodus_witness.c). That padding is part of the
 * signed bytes, so it is pinned here rather than assumed. */
static const uint8_t KAT_CHAIN_ID[32] = {
    0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9,
    0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* ── §A — the strictness predicate itself ─────────────────────────── */

static void test_strict_set_is_exactly_07_08(void) {
    TEST("§A strict set is exactly {PREPARED 0x07, VIEWOK 0x08}");
    if (!nodus_sign_purpose_is_strict(NODUS_PURPOSE_PREPARED)) {
        FAIL("PREPARED (0x07) must be strict"); return; }
    if (!nodus_sign_purpose_is_strict(NODUS_PURPOSE_VIEWOK)) {
        FAIL("VIEWOK (0x08) must be strict"); return; }
    /* The shipped-client bridge must stay EXACTLY as wide as it was:
     * none of 0x01-0x05 may become strict by accident. 0x06 is
     * reserved-unimplemented, 0x09 unassigned. */
    if (nodus_sign_purpose_is_strict(NODUS_PURPOSE_AUTH_CHALLENGE)) {
        FAIL("AUTH_CHALLENGE (0x01) must NOT be strict"); return; }
    if (nodus_sign_purpose_is_strict(NODUS_PURPOSE_KYBER_BIND)) {
        FAIL("KYBER_BIND (0x02) must NOT be strict"); return; }
    if (nodus_sign_purpose_is_strict(NODUS_PURPOSE_T3_ENVELOPE)) {
        FAIL("T3_ENVELOPE (0x03) must NOT be strict"); return; }
    if (nodus_sign_purpose_is_strict(NODUS_PURPOSE_VALUE_STORE)) {
        FAIL("VALUE_STORE (0x04) must NOT be strict"); return; }
    if (nodus_sign_purpose_is_strict(NODUS_PURPOSE_CERT)) {
        FAIL("CERT (0x05) must NOT be strict"); return; }
    if (nodus_sign_purpose_is_strict(0x00)) { FAIL("0x00 strict"); return; }
    if (nodus_sign_purpose_is_strict(0x06)) { FAIL("0x06 strict"); return; }
    if (nodus_sign_purpose_is_strict(0x09)) { FAIL("0x09 strict"); return; }
    PASS();
}

/* ── §B — the 116-byte layout, written out in full ────────────────── */

static void test_prepared_preimage_kat(void) {
    TEST("§B PREPARED preimage KAT — 116 bytes, byte for byte");

    const uint32_t view   = 0x01020304u;
    const uint64_t height = 0x0102030405060708ull;
    uint8_t tx_hash[NODUS_T3_TX_HASH_LEN];
    memset(tx_hash, 0x77, sizeof(tx_hash));

    static const uint8_t expect[PREP_LEN] = {
        /* [0..7] "prepared" — 8 ASCII bytes, no NUL */
        0x70, 0x72, 0x65, 0x70, 0x61, 0x72, 0x65, 0x64,
        /* [8..39] chain_id: 16 significant bytes then the 16-byte pad */
        0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9,
        0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9, 0xE9,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        /* [40..43] view 0x01020304, BIG-endian */
        0x01, 0x02, 0x03, 0x04,
        /* [44..51] height 0x0102030405060708, BIG-endian */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        /* [52..115] tx_hash, 64 bytes */
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
        0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    };

    uint8_t got[PREP_LEN];
    build_prepared_preimage(got, KAT_CHAIN_ID, view, height, tx_hash);

    for (int i = 0; i < PREP_LEN; i++) {
        if (got[i] != expect[i]) {
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "offset %d: got 0x%02X want 0x%02X", i, got[i], expect[i]);
            FAIL(msg);
            return;
        }
    }
    /* Anti-vacuity for the tag: "prepared" occupies 8 bytes with NO NUL,
     * so byte 8 belongs to chain_id and is not a terminator. */
    if (expect[7] != 0x64) { FAIL("byte 7 must be 'd'"); return; }
    if (expect[8] == 0x00) { FAIL("byte 8 is chain_id, not a NUL"); return; }
    PASS();
}

/* ── Fixture for §C/§D — a REAL chain database ────────────────────── */

typedef struct {
    uint8_t pk[NODUS_PK_BYTES];
    uint8_t sk[4896];
    uint8_t id[NODUS_T3_WITNESS_ID_LEN];
} dsep_peer_t;

static void dsep_rmrf(const char *path) {
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
                dsep_rmrf(child);
            }
            closedir(d);
        }
        (void)rmdir(path);
    } else {
        (void)unlink(path);
    }
}

/* members[0] is US. The chain database is REAL and its validator table is
 * EMPTY — the (rc 0, count 0) pre-genesis answer that resolves voter keys
 * through the documented gossip roster while the chain_id stays NON-ZERO.
 *
 * ⚠ A DB-LESS FIXTURE CANNOT BE USED HERE. With no `w->db` and a non-zero
 * chain_id, load_committee_at_height returns -1 (the DG-1 "holds a chain,
 * cannot read it" row) and verify_prepared_cert fails closed before it
 * looks at any signature — every leg below would then pass vacuously. */
static nodus_witness_t *dsep_fixture(const dsep_peer_t *members, int n,
                                      const char *dir,
                                      const uint8_t cid16[16]) {
    nodus_witness_t *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    nodus_server_t *srv = calloc(1, sizeof(*srv));
    if (!srv) { free(w); return NULL; }
    memcpy(srv->identity.pk.bytes, members[0].pk, NODUS_PK_BYTES);
    memcpy(srv->identity.sk.bytes, members[0].sk,
           sizeof(srv->identity.sk.bytes));
    w->server = srv;
    memcpy(w->my_id, members[0].id, NODUS_T3_WITNESS_ID_LEN);

    for (int i = 0; i < n; i++) {
        uint32_t s = w->roster.n_witnesses++;
        memcpy(w->roster.witnesses[s].witness_id, members[i].id,
               NODUS_T3_WITNESS_ID_LEN);
        memcpy(w->roster.witnesses[s].pubkey, members[i].pk,
               DNAC_PUBKEY_SIZE);
        w->roster.witnesses[s].active = true;
    }

    snprintf(w->data_path, sizeof(w->data_path), "%s", dir);
    if (nodus_witness_create_chain_db(w, cid16) != 0 || !w->db) {
        free(srv); free(w); return NULL;
    }

    /* Cache sentinel, and it is load-bearing: a calloc'd witness has
     * cached_committee_epoch_start == 0 and every lookup below queries
     * epoch 0, so leaving the zero takes the cache-HIT branch and never
     * reads the table. Production sets UINT64_MAX at init for the same
     * reason. */
    w->cached_committee_epoch_start = UINT64_MAX;
    w->cached_committee_count = 0;

    nodus_witness_bft_config_init(&w->bft_config, w->roster.n_witnesses);
    return w;
}

static void dsep_fixture_free(nodus_witness_t *w, const char *dir) {
    if (w) {
        if (w->db) { sqlite3_close(w->db); w->db = NULL; }
        free(w->server);
        free(w);
    }
    dsep_rmrf(dir);
}

/* Sign through the SAME wrapper production uses, so purpose 0x07's
 * strictness applies here exactly as it applies to a validator. */
static int dsep_sign_prepared(uint8_t out[NODUS_SIG_BYTES],
                               const dsep_peer_t *p,
                               const uint8_t pre[PREP_LEN]) {
    nodus_sig_t sig;
    nodus_seckey_t sk;
    memcpy(sk.bytes, p->sk, sizeof(sk.bytes));
    if (nodus_sign_prepared_vote(&sig, pre, PREP_LEN, &sk) != 0) return -1;
    memcpy(out, sig.bytes, NODUS_SIG_BYTES);
    return 0;
}

/* ── §C + §D — production binding and the substitution matrix ─────── */

static void test_prepared_cert_production_binding(void) {
    TEST("§C/§D production preimage + chain_id/view/height/hash binding");

    static dsep_peer_t members[5];
    for (int i = 0; i < 5; i++) {
        if (qgp_dsa87_keypair(members[i].pk, members[i].sk) != 0) {
            FAIL("keygen"); return; }
        uint8_t d[64];
        if (qgp_sha3_512(members[i].pk, NODUS_PK_BYTES, d) != 0) {
            FAIL("witness id hash"); return; }
        memcpy(members[i].id, d, NODUS_T3_WITNESS_ID_LEN);
    }

    char dir_a[] = "/tmp/test_sign_domain_sep_a_XXXXXX";
    char dir_b[] = "/tmp/test_sign_domain_sep_b_XXXXXX";
    if (mkdtemp(dir_a) == NULL) { FAIL("temp dir A"); return; }
    if (mkdtemp(dir_b) == NULL) { dsep_rmrf(dir_a); FAIL("temp dir B"); return; }

    uint8_t cid_a[16]; memset(cid_a, 0xE9, sizeof(cid_a));
    uint8_t cid_b[16]; memset(cid_b, 0xA5, sizeof(cid_b));

    nodus_witness_t *w  = dsep_fixture(members, 5, dir_a, cid_a);
    nodus_witness_t *w2 = dsep_fixture(members, 5, dir_b, cid_b);

#define DSEP_BAIL(msg) do { \
        dsep_fixture_free(w2, dir_b); \
        dsep_fixture_free(w, dir_a); \
        FAIL(msg); \
        return; \
    } while (0)

    if (!w || !w2) DSEP_BAIL("fixture");

    /* THE ANTI-VACUITY GATE. A quorum of 0 makes every certificate verify
     * and everything below would measure nothing. */
    if (w->roster.n_witnesses != 5)  DSEP_BAIL("roster must seat 5");
    if (w->bft_config.quorum == 0)
        DSEP_BAIL("quorum 0 — bft_config_init took its consensus-disabled "
                  "branch and nothing below is being measured");
    if (w->bft_config.quorum != 4)   DSEP_BAIL("quorum must be (2*5)/3+1 = 4");
    if (w2->bft_config.quorum != 4)  DSEP_BAIL("w2 quorum must be 4");

    /* The fixture's chain_id really is the padded 32-byte value §B pinned,
     * otherwise the chain_id leg would be exercising the wrong field. */
    if (memcmp(w->chain_id, KAT_CHAIN_ID, 32) != 0)
        DSEP_BAIL("create_chain_db must zero-pad the 16-byte id to 32");
    if (memcmp(w->chain_id, w2->chain_id, 32) == 0)
        DSEP_BAIL("the two fixtures must hold DIFFERENT chains");

    /* A height inside the bootstrap range, so the committee lookup gives
     * the (rc 0, count 0) pre-genesis answer. */
    const uint64_t H = 5;
    const uint32_t V = 2;
    uint8_t txh[NODUS_T3_TX_HASH_LEN];
    memset(txh, 0x77, sizeof(txh));

    uint8_t pre[PREP_LEN];
    build_prepared_preimage(pre, w->chain_id, V, H, txh);

    nodus_t3_cert_entry_t cert[4];
    memset(cert, 0, sizeof(cert));
    for (int i = 0; i < 4; i++) {
        memcpy(cert[i].voter_id, members[i].id, NODUS_T3_WITNESS_ID_LEN);
        if (dsep_sign_prepared(cert[i].signature, &members[i], pre) != 0)
            DSEP_BAIL("prepared sign");
    }

    /* §C — production must accept signatures made over THIS FILE's bytes.
     * If it does not, the two layouts have diverged, and §B's explicit
     * KAT is no longer a statement about production. */
    if (!nodus_witness_bft_verify_prepared_cert(w, H, V, txh, cert, 4))
        DSEP_BAIL("§C production rejected a certificate over the "
                  "independently built 116-byte preimage");

    /* §D — each field bound on its own. */
    if (nodus_witness_bft_verify_prepared_cert(w, H, V + 1, txh, cert, 4))
        DSEP_BAIL("§D view: the same sigs must not prove another view");
    if (nodus_witness_bft_verify_prepared_cert(w, H + 1, V, txh, cert, 4))
        DSEP_BAIL("§D height: nor another height");

    uint8_t other_txh[NODUS_T3_TX_HASH_LEN];
    memset(other_txh, 0x78, sizeof(other_txh));
    if (nodus_witness_bft_verify_prepared_cert(w, H, V, other_txh, cert, 4))
        DSEP_BAIL("§D tx_hash: nor another value");

    /* chain_id — the leg that exists only because of Faz 2A. chain_id is
     * NOT an argument of the verify call; it is read from the witness. So
     * the only way to vary it is a second witness holding a different
     * chain, with the SAME roster so voter resolution is unchanged and
     * the chain identity is the ONLY difference. Before Faz 2A this
     * certificate verified on both — the post-wipe replay. */
    if (nodus_witness_bft_verify_prepared_cert(w2, H, V, txh, cert, 4))
        DSEP_BAIL("§D chain_id: a certificate harvested from one chain "
                  "must NOT verify on another");

    /* Anti-vacuity for that leg: w2 is not simply refusing everything. */
    uint8_t pre_b[PREP_LEN];
    build_prepared_preimage(pre_b, w2->chain_id, V, H, txh);
    nodus_t3_cert_entry_t cert_b[4];
    memset(cert_b, 0, sizeof(cert_b));
    for (int i = 0; i < 4; i++) {
        memcpy(cert_b[i].voter_id, members[i].id, NODUS_T3_WITNESS_ID_LEN);
        if (dsep_sign_prepared(cert_b[i].signature, &members[i], pre_b) != 0)
            DSEP_BAIL("prepared sign (chain B)");
    }
    if (!nodus_witness_bft_verify_prepared_cert(w2, H, V, txh, cert_b, 4))
        DSEP_BAIL("§D anti-vacuity: w2 must ACCEPT a certificate over its "
                  "OWN chain_id, or the refusal above is not about chains");

#undef DSEP_BAIL

    dsep_fixture_free(w2, dir_b);
    dsep_fixture_free(w, dir_a);
    PASS();
}

/* ── §E — 0x07 and 0x08 do not interchange ────────────────────────── */

static void test_strict_cross_domain_rejects(void) {
    TEST("§E strict domains cross-reject (0x07 <-> 0x08)");

    uint8_t data[PREP_LEN];
    uint8_t tx_hash[NODUS_T3_TX_HASH_LEN];
    memset(tx_hash, 0x77, sizeof(tx_hash));
    build_prepared_preimage(data, KAT_CHAIN_ID, 0x01020304u,
                             0x0102030405060708ull, tx_hash);

    nodus_sig_t sig07, sig08;
    if (nodus_sign_tagged(&sig07, NODUS_PURPOSE_PREPARED,
                           data, sizeof(data), &g_sk) != 0) {
        FAIL("sign 0x07"); return; }
    if (nodus_sign_tagged(&sig08, NODUS_PURPOSE_VIEWOK,
                           data, sizeof(data), &g_sk) != 0) {
        FAIL("sign 0x08"); return; }

    /* Controls first — without these, "everything fails" would pass. */
    if (nodus_verify_tagged(&sig07, NODUS_PURPOSE_PREPARED,
                             data, sizeof(data), &g_pk) != 0) {
        FAIL("control: 0x07 must verify under 0x07"); return; }
    if (nodus_verify_tagged(&sig08, NODUS_PURPOSE_VIEWOK,
                             data, sizeof(data), &g_pk) != 0) {
        FAIL("control: 0x08 must verify under 0x08"); return; }

    if (nodus_verify_tagged(&sig07, NODUS_PURPOSE_VIEWOK,
                             data, sizeof(data), &g_pk) == 0) {
        FAIL("a PREPARED sig verified as VIEWOK"); return; }
    if (nodus_verify_tagged(&sig08, NODUS_PURPOSE_PREPARED,
                             data, sizeof(data), &g_pk) == 0) {
        FAIL("a VIEWOK sig verified as PREPARED"); return; }

    /* ⚠ NOT ASSERTED: that sig07 and sig08 differ byte-for-byte. That
     * would be VACUOUS. DILITHIUM_RANDOMIZED_SIGNING is defined
     * (shared/crypto/sign/dsa/config.h:6), so sign.c:288-289 draws a
     * fresh `rnd` per call and ANY two signatures differ — including the
     * two RAW ones the pre-Faz-2A code produced. The check would pass
     * against the very defect it appeared to test.
     *
     * The non-vacuous form of the same idea: rebuild the NDS1 preimage
     * HERE and show the strict signer signed the TAGGED bytes carrying
     * purpose 0x07, not the ones carrying 0x08. This also pins the NDS1
     * header layout: "NDS1"(4) | purpose(1) | data_len BE(4) | data. */
    uint8_t nds1_07[9 + PREP_LEN];
    uint8_t nds1_08[9 + PREP_LEN];
    for (int variant = 0; variant < 2; variant++) {
        uint8_t *b = (variant == 0) ? nds1_07 : nds1_08;
        memcpy(b, "NDS1", 4);
        b[4] = (variant == 0) ? NODUS_PURPOSE_PREPARED : NODUS_PURPOSE_VIEWOK;
        b[5] = (uint8_t)(((uint32_t)PREP_LEN) >> 24);
        b[6] = (uint8_t)(((uint32_t)PREP_LEN) >> 16);
        b[7] = (uint8_t)(((uint32_t)PREP_LEN) >> 8);
        b[8] = (uint8_t)(((uint32_t)PREP_LEN) & 0xFF);
        memcpy(b + 9, data, PREP_LEN);
    }
    /* The 9 and 4 above are spelled out on purpose — a KAT that reuses
     * the constant under test cannot catch it moving. Pin them together. */
    if (NODUS_SIGN_HEADER_LEN != 9) { FAIL("NDS1 header must be 9 B"); return; }
    if (NODUS_SIGN_MAGIC_LEN != 4)  { FAIL("NDS1 magic must be 4 B"); return; }
    if (nds1_07[8] != 116) { FAIL("NDS1 length field must say 116"); return; }

    if (nodus_verify(&sig07, nds1_07, sizeof(nds1_07), &g_pk) != 0) {
        FAIL("the strict signer must sign the NDS1-tagged bytes for 0x07");
        return; }
    if (nodus_verify(&sig08, nds1_08, sizeof(nds1_08), &g_pk) != 0) {
        FAIL("the strict signer must sign the NDS1-tagged bytes for 0x08");
        return; }
    if (nodus_verify(&sig07, nds1_08, sizeof(nds1_08), &g_pk) == 0) {
        FAIL("the 0x07 sig must not be over the 0x08 preimage"); return; }
    PASS();
}

/* ── §F — the raw-verify bypass is really lifted ──────────────────── */

static void test_strict_raw_signature_refused(void) {
    TEST("§F a RAW signature is refused for 0x07 and 0x08");

    uint8_t data[PREP_LEN];
    uint8_t tx_hash[NODUS_T3_TX_HASH_LEN];
    memset(tx_hash, 0x77, sizeof(tx_hash));
    build_prepared_preimage(data, KAT_CHAIN_ID, 0x01020304u,
                             0x0102030405060708ull, tx_hash);

    nodus_sig_t raw;
    if (nodus_sign(&raw, data, sizeof(data), &g_sk) != 0) {
        FAIL("raw sign"); return; }

    /* Control: the raw signature IS genuinely valid raw. Without this,
     * the refusals below could pass because the signature was broken. */
    if (nodus_verify(&raw, data, sizeof(data), &g_pk) != 0) {
        FAIL("control: the raw signature must be valid raw"); return; }

    if (nodus_verify_tagged(&raw, NODUS_PURPOSE_PREPARED,
                             data, sizeof(data), &g_pk) == 0) {
        FAIL("a RAW signature was accepted for PREPARED (0x07)"); return; }
    if (nodus_verify_tagged(&raw, NODUS_PURPOSE_VIEWOK,
                             data, sizeof(data), &g_pk) == 0) {
        FAIL("a RAW signature was accepted for VIEWOK (0x08)"); return; }

    /* The signing half stated directly: what a strict sign emits is NOT a
     * raw signature over the data. */
    nodus_sig_t strict;
    if (nodus_sign_tagged(&strict, NODUS_PURPOSE_PREPARED,
                           data, sizeof(data), &g_sk) != 0) {
        FAIL("strict sign"); return; }
    if (nodus_verify(&strict, data, sizeof(data), &g_pk) == 0) {
        FAIL("a strict-purpose signature verified as raw — the signer did "
             "not apply the NDS1 tag"); return; }
    PASS();
}

/* ── §G — the compat bridge is exactly as wide as before ──────────── */

static void test_compat_bridge_unchanged(void) {
    TEST("§G the shipped-client compat bridge (0x01-0x05) is unchanged");

    uint8_t nonce[NODUS_NONCE_LEN];
    nodus_random(nonce, sizeof(nonce));

    /* Verify side: a RAW signature is STILL accepted for a NON-strict
     * purpose. Goes red if someone deletes the trailing raw fallback in
     * nodus_verify_tagged while "tidying" the bridge. */
    nodus_sig_t raw;
    if (nodus_sign(&raw, nonce, sizeof(nonce), &g_sk) != 0) {
        FAIL("raw sign"); return; }
    if (nodus_verify_tagged(&raw, NODUS_PURPOSE_AUTH_CHALLENGE,
                             nonce, sizeof(nonce), &g_pk) != 0) {
        FAIL("compat fallback missing — pre-11467980 clients cannot auth");
        return; }

    /* Sign side: a NON-strict tagged sign still emits RAW bytes, which is
     * what an old client verifies. Goes red if the strict branch is
     * widened to cover 0x01-0x05. */
    nodus_sig_t compat;
    if (nodus_sign_tagged(&compat, NODUS_PURPOSE_AUTH_CHALLENGE,
                           nonce, sizeof(nonce), &g_sk) != 0) {
        FAIL("compat sign"); return; }
    if (nodus_verify(&compat, nonce, sizeof(nonce), &g_pk) != 0) {
        FAIL("a non-strict tagged sign no longer emits raw bytes — the "
             "compat bridge was narrowed"); return; }
    PASS();
}

int main(void) {
    printf("Nodus domain-separation sign/verify tests (C2 fix)\n");
    printf("=================================================\n");

    if (setup_keypair() != 0) {
        fprintf(stderr, "FATAL: keypair generation failed\n");
        return 1;
    }

    test_auth_challenge_roundtrip();
    test_kyber_bind_roundtrip();
    test_t3_envelope_roundtrip();
    test_value_store_roundtrip();
    test_cert_roundtrip();
    /* STILL DISABLED, AND DELIBERATELY SO — these two cover purposes
     * 0x01-0x05, where the v0.17.5 compat bridge remains in force:
     * nodus_sign_tagged() signs those raw so pre-11467980 clients can
     * verify, and the verify side keeps its raw fallback for them. O15N
     * Faz 2A did NOT narrow that bridge — §G asserts it is exactly as
     * wide as before, in BOTH directions.
     *
     * ⚠ Do not "re-enable these now that domain separation is back": it
     * is back only for the two STRICT witness-to-witness purposes, and
     * their cross-rejection is covered by §E below. Re-enable these two
     * only once every deployed client ships commit 11467980 or later,
     * at which point the bridge itself can be deleted. */
    /* test_cross_domain_fails(); */
    /* test_every_pair_rejects(); */
    test_raw_sig_accepted_via_fallback();
    test_tampered_data_fails();

    /* ── O15N Faz 2A — the STRICT domains ─────────────────────────── */
    printf("\nO15N Faz 2A — strict domains (PREPARED 0x07, VIEWOK 0x08)\n");
    printf("---------------------------------------------------------\n");
    test_strict_set_is_exactly_07_08();
    test_prepared_preimage_kat();
    test_prepared_cert_production_binding();
    test_strict_cross_domain_rejects();
    test_strict_raw_signature_refused();
    test_compat_bridge_unchanged();

    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
