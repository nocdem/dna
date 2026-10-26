/**
 * Nodus — the owner-signed chain query `qa` (DHT v2 package 3d)
 *
 * Design docs/plans/2026-10-26-dht-v2-3d-no-login-design.md rev 5 §3;
 * decisions/2026-10-26-wallet-no-node-login.md, decisions/2026-10-26-kurultay-
 * 45-summary.md (khan decision 1). Code under test: nodus/src/protocol/
 * nodus_owner_query.{h,c} (the RFC 0002 envelope of shared/dht2).
 *
 * WHAT IT PROVES (each case would be false if the check it names were
 * missing):
 *   1. ACCEPT: a `qa` built by nodus_oq_build for each of the five owner-only
 *      reads opens: the signer's key, its fingerprint (SHA3-512) and the
 *      signed `o` come back exactly.
 *   2. PAYLOAD: {c, m, o, s} encodes to the one canonical DAG-CBOR and decodes
 *      back; a different key order, an extra key, a trailing byte, a method
 *      name over the bound, a wrong-size field are refused.
 *   3. REJECTS, each by its own result:
 *        wrong domain (ctx)            -> signature  (the signature is under
 *                                          another domain)
 *        wrong payload type            -> malformed  (checked explicitly)
 *        one flipped signature byte    -> signature
 *        wrong chain id `c`            -> binding
 *        wrong method `m`              -> binding
 *        `s` != this session's T       -> binding
 *        `s` of ANOTHER session        -> binding (a copied qa cannot move)
 *        a truncated / oversized / empty envelope, NULL arguments -> malformed
 *   4. FIND: the top-level `qa` of a T2 request frame is found beside `a`;
 *      absent -> 1; twice, not a byte string, not a map -> -1.
 *   5. `o` PER METHOD: the subject a request names must equal the signed `o`
 *      (nodus_oq_subject_ok): utxo / addr_history by the hex-decoded owner,
 *      delegations by SHA3-512(pubkey) with a ZERO or short pubkey refused,
 *      msig by the vault address — and the G8.1 member rule
 *      (nodus_witness_msig_member_ok, the function the witness handler runs)
 *      with the `qa` key: a member passes, a non-member, a wrong vault
 *      address and a zero key do not.
 *
 * NOT covered here: the handlers around these (nodus_witness_handle_dnac_anon
 * needs a full witness; test_msig_query / test_addr_index drive the identified
 * path through the real dispatcher). The per-method `o` is tested at the
 * module and rule level above, which is what the handlers call.
 *
 * Requires: a default build (no flags, no environment). No sockets, no files.
 * Leaves behind: nothing. How it can lie: the bad-signature case flips one
 * byte of the LAST bytes of the envelope; if the canonical envelope ever put
 * another field last the flip would land in the payload and the case would
 * still FAIL-or-pass on a different result (it requires exactly "signature").
 */

#include "protocol/nodus_owner_query.h"
#include "protocol/nodus_cbor.h"
#include "witness/nodus_witness_addr_index.h"
#include "dht2/dht2_cbor.h"
#include "dht2/dht2_envelope.h"
#include "dht2/dht2_types.h"
#include "dnac/msig_wire.h"
#include "crypto/nodus_identity.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST(name) do { printf("  %-66s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)

static int passed = 0;
static int failed = 0;

static nodus_identity_t g_owner;       /* the wallet's key */
static nodus_identity_t g_other;       /* another wallet's key */
static uint8_t g_chain[NODUS_OQ_CHAIN_LEN];
static uint8_t g_t[NODUS_OQ_T_LEN];    /* this session's T */
static uint8_t g_t2[NODUS_OQ_T_LEN];   /* another session's T */

static const char *const k_methods[] = {
    "dnac_utxo", "dnac_addr_history", "dnac_delegations",
    "dnac_msig_utxo", "dnac_msig_addr_history",
};

static uint8_t g_env[NODUS_OQ_ENV_MAX];
static size_t  g_env_len;

static int build(const char *method, const uint8_t o[64], const uint8_t t[64]) {
    g_env_len = 0;
    return nodus_oq_build(g_chain, method, o, t, g_owner.sk.bytes,
                          g_owner.pk.bytes, g_env, sizeof(g_env), &g_env_len);
}

/* ── 1. accept ───────────────────────────────────────────────────── */

static void test_accept(void) {
    TEST("accept: each of the five methods; signer, fp and o come back");
    uint8_t o[64];
    nodus_oq_proof_t pf;
    for (size_t m = 0; m < sizeof(k_methods) / sizeof(k_methods[0]); m++) {
        for (int i = 0; i < 64; i++) o[i] = (uint8_t)(m * 40 + i);
        if (build(k_methods[m], o, g_t) != 0) { FAIL("build"); return; }
        if (nodus_oq_open(g_env, g_env_len, g_chain, k_methods[m], g_t, &pf) !=
            NODUS_OQ_OK) {
            FAIL("a valid qa was refused");
            return;
        }
        uint8_t fp[64];
        qgp_sha3_512(g_owner.pk.bytes, NODUS_OQ_PK_LEN, fp);
        if (memcmp(pf.pk, g_owner.pk.bytes, NODUS_OQ_PK_LEN) != 0 ||
            memcmp(pf.fp, fp, 64) != 0 || memcmp(pf.fp, g_owner.node_id.bytes, 64) != 0 ||
            memcmp(pf.o, o, 64) != 0) {
            FAIL("proof does not match the signer / o");
            return;
        }
    }
    PASS();
}

/* ── 2. payload ──────────────────────────────────────────────────── */

static void test_payload(void) {
    TEST("payload: canonical {c,m,o,s}; strict decode refuses everything else");
    nodus_oq_payload_t p, q;
    memset(&p, 0, sizeof(p));
    memcpy(p.chain, g_chain, 32);
    strcpy(p.method, "dnac_utxo");
    memset(p.o, 0x11, 64);
    memcpy(p.s, g_t, 64);
    uint8_t buf[NODUS_OQ_PAYLOAD_MAX];
    size_t n = 0, nsz = 0;
    if (nodus_oq_payload_encode(&p, NULL, 0, &nsz) != 0 ||
        nodus_oq_payload_encode(&p, buf, sizeof(buf), &n) != 0 || n != nsz) {
        FAIL("encode / size-only disagree");
        return;
    }
    /* exact bytes: a4 61 63 58 20 <32> 61 6d 69 "dnac_utxo" 61 6f 58 40 <64> 61 73 58 40 <64> */
    if (n != 1 + (2 + 2 + 32) + (2 + 1 + 9) + (2 + 2 + 64) + (2 + 2 + 64) ||
        buf[0] != 0xa4 || buf[1] != 0x61 || buf[2] != 'c' || buf[3] != 0x58 ||
        buf[4] != 0x20 || buf[37] != 0x61 || buf[38] != 'm' || buf[39] != 0x69) {
        FAIL("not the canonical bytes");
        return;
    }
    if (nodus_oq_payload_decode(buf, n, &q) != 0 || memcmp(&p, &q, sizeof(p)) != 0) {
        FAIL("round trip");
        return;
    }
    /* trailing byte */
    uint8_t tail[NODUS_OQ_PAYLOAD_MAX + 1];
    memcpy(tail, buf, n);
    tail[n] = 0;
    if (nodus_oq_payload_decode(tail, n + 1, &q) == 0) { FAIL("trailing byte accepted"); return; }
    /* keys in the wrong order: m before c */
    {
        dht2_cbor_wr_t w;
        uint8_t sw[NODUS_OQ_PAYLOAD_MAX];
        dht2_cbor_wr_init(&w, sw, sizeof(sw));
        dht2_cbor_wr_map(&w, 4);
        dht2_cbor_wr_key(&w, "m");
        dht2_cbor_wr_text(&w, (const uint8_t *)"dnac_utxo", 9);
        dht2_cbor_wr_key(&w, "c");
        dht2_cbor_wr_bytes(&w, p.chain, 32);
        dht2_cbor_wr_key(&w, "o");
        dht2_cbor_wr_bytes(&w, p.o, 64);
        dht2_cbor_wr_key(&w, "s");
        dht2_cbor_wr_bytes(&w, p.s, 64);
        if (!dht2_cbor_wr_ok(&w) || nodus_oq_payload_decode(sw, w.len, &q) == 0) {
            FAIL("out-of-order keys accepted");
            return;
        }
    }
    /* an extra key */
    {
        dht2_cbor_wr_t w;
        uint8_t ex[NODUS_OQ_PAYLOAD_MAX + 16];
        dht2_cbor_wr_init(&w, ex, sizeof(ex));
        dht2_cbor_wr_map(&w, 5);
        dht2_cbor_wr_key(&w, "c");
        dht2_cbor_wr_bytes(&w, p.chain, 32);
        dht2_cbor_wr_key(&w, "m");
        dht2_cbor_wr_text(&w, (const uint8_t *)"dnac_utxo", 9);
        dht2_cbor_wr_key(&w, "o");
        dht2_cbor_wr_bytes(&w, p.o, 64);
        dht2_cbor_wr_key(&w, "s");
        dht2_cbor_wr_bytes(&w, p.s, 64);
        dht2_cbor_wr_key(&w, "x");
        dht2_cbor_wr_bytes(&w, p.o, 1);
        if (!dht2_cbor_wr_ok(&w) || nodus_oq_payload_decode(ex, w.len, &q) == 0) {
            FAIL("an extra key accepted");
            return;
        }
    }
    /* a method over the bound (decode), an empty method (encode) */
    {
        dht2_cbor_wr_t w;
        uint8_t lg[NODUS_OQ_PAYLOAD_MAX + 16];
        char longm[NODUS_OQ_METHOD_MAX + 2];
        memset(longm, 'x', sizeof(longm));
        dht2_cbor_wr_init(&w, lg, sizeof(lg));
        dht2_cbor_wr_map(&w, 4);
        dht2_cbor_wr_key(&w, "c");
        dht2_cbor_wr_bytes(&w, p.chain, 32);
        dht2_cbor_wr_key(&w, "m");
        dht2_cbor_wr_text(&w, (const uint8_t *)longm, sizeof(longm));
        dht2_cbor_wr_key(&w, "o");
        dht2_cbor_wr_bytes(&w, p.o, 64);
        dht2_cbor_wr_key(&w, "s");
        dht2_cbor_wr_bytes(&w, p.s, 64);
        if (!dht2_cbor_wr_ok(&w) || nodus_oq_payload_decode(lg, w.len, &q) == 0) {
            FAIL("a method over the bound accepted");
            return;
        }
    }
    nodus_oq_payload_t none = p;
    none.method[0] = '\0';
    size_t dummy = 0;
    if (nodus_oq_payload_encode(&none, buf, sizeof(buf), &dummy) == 0) {
        FAIL("an empty method encoded");
        return;
    }
    if (nodus_oq_payload_decode(buf, 0, &q) == 0 || nodus_oq_payload_decode(NULL, 5, &q) == 0) {
        FAIL("empty / NULL input accepted");
        return;
    }
    PASS();
}

/* ── 3. rejects ──────────────────────────────────────────────────── */

static int seal_custom(const char *domain, const char *ptype, const uint8_t *chain,
                       const char *method, const uint8_t *o, const uint8_t *t) {
    nodus_oq_payload_t p;
    uint8_t payload[NODUS_OQ_PAYLOAD_MAX];
    size_t plen = 0;
    memset(&p, 0, sizeof(p));
    memcpy(p.chain, chain, 32);
    snprintf(p.method, sizeof(p.method), "%s", method);
    memcpy(p.o, o, 64);
    memcpy(p.s, t, 64);
    if (nodus_oq_payload_encode(&p, payload, sizeof(payload), &plen) != 0) return -1;
    g_env_len = 0;
    return dht2_env_seal(domain, (const uint8_t *)ptype, strlen(ptype), payload, plen,
                         g_owner.sk.bytes, g_owner.pk.bytes, g_env, sizeof(g_env),
                         &g_env_len) == DHT2_OK ? 0 : -1;
}

static int open_rc(const char *method, const uint8_t *t) {
    nodus_oq_proof_t pf;
    int rc = nodus_oq_open(g_env, g_env_len, g_chain, method, t, &pf);
    if (rc != NODUS_OQ_OK) {
        /* nothing of a refused proof may be left behind */
        uint8_t acc = 0;
        for (size_t i = 0; i < sizeof(pf); i++) acc |= ((const uint8_t *)&pf)[i];
        if (acc != 0) return 100;
    }
    return rc;
}

static void test_rejects(void) {
    uint8_t o[64];
    memset(o, 0x22, sizeof(o));
    uint8_t chain2[32];
    memcpy(chain2, g_chain, 32);
    chain2[0] ^= 1;

    TEST("reject: wrong domain (ctx) -> signature");
    if (seal_custom(DHT2_DOMAIN_LIST, NODUS_OQ_PAYLOAD_TYPE, g_chain, "dnac_utxo", o, g_t) != 0)
        FAIL("seal");
    else if (open_rc("dnac_utxo", g_t) == NODUS_OQ_E_SIGNATURE) PASS();
    else FAIL("a qa under another domain opened");

    TEST("reject: wrong payload type -> malformed");
    if (seal_custom(NODUS_OQ_DOMAIN, DHT2_PT_LIST, g_chain, "dnac_utxo", o, g_t) != 0)
        FAIL("seal");
    else if (open_rc("dnac_utxo", g_t) == NODUS_OQ_E_MALFORMED) PASS();
    else FAIL("a qa with another payload type opened");

    TEST("reject: one flipped signature byte -> signature");
    if (build("dnac_utxo", o, g_t) != 0) FAIL("build");
    else {
        g_env[g_env_len - 5] ^= 0x01;     /* the signature is the last field */
        if (open_rc("dnac_utxo", g_t) == NODUS_OQ_E_SIGNATURE) PASS();
        else FAIL("a damaged signature was not reported as such");
    }

    TEST("reject: wrong chain id c -> binding");
    if (seal_custom(NODUS_OQ_DOMAIN, NODUS_OQ_PAYLOAD_TYPE, chain2, "dnac_utxo", o, g_t) != 0)
        FAIL("seal");
    else if (open_rc("dnac_utxo", g_t) == NODUS_OQ_E_BINDING) PASS();
    else FAIL("another chain's qa opened");

    TEST("reject: wrong method m -> binding");
    if (build("dnac_addr_history", o, g_t) != 0) FAIL("build");
    else if (open_rc("dnac_utxo", g_t) == NODUS_OQ_E_BINDING) PASS();
    else FAIL("a qa for another method opened");

    TEST("reject: s != this session's T -> binding");
    if (build("dnac_utxo", o, g_t) != 0) FAIL("build");
    else {
        uint8_t bad[64];
        memcpy(bad, g_t, 64);
        bad[63] ^= 1;
        if (open_rc("dnac_utxo", bad) == NODUS_OQ_E_BINDING) PASS();
        else FAIL("a qa bound to another T opened");
    }

    TEST("reject: s of ANOTHER session (a copied qa) -> binding");
    if (build("dnac_utxo", o, g_t2) != 0) FAIL("build");
    else if (open_rc("dnac_utxo", g_t) == NODUS_OQ_E_BINDING) PASS();
    else FAIL("a qa built for another session opened here");

    TEST("reject: truncated / oversized / empty envelope, NULL -> malformed");
    if (build("dnac_utxo", o, g_t) != 0) { FAIL("build"); return; }
    {
        nodus_oq_proof_t pf;
        int ok = 1;
        ok = ok && nodus_oq_open(g_env, g_env_len / 2, g_chain, "dnac_utxo", g_t, &pf) !=
                       NODUS_OQ_OK;
        ok = ok && nodus_oq_open(g_env, 0, g_chain, "dnac_utxo", g_t, &pf) ==
                       NODUS_OQ_E_MALFORMED;
        ok = ok && nodus_oq_open(g_env, NODUS_OQ_ENV_MAX + 1, g_chain, "dnac_utxo", g_t,
                                 &pf) == NODUS_OQ_E_MALFORMED;
        ok = ok && nodus_oq_open(NULL, 10, g_chain, "dnac_utxo", g_t, &pf) ==
                       NODUS_OQ_E_MALFORMED;
        ok = ok && nodus_oq_open(g_env, g_env_len, NULL, "dnac_utxo", g_t, &pf) ==
                       NODUS_OQ_E_MALFORMED;
        ok = ok && nodus_oq_open(g_env, g_env_len, g_chain, "dnac_utxo", g_t, NULL) ==
                       NODUS_OQ_E_MALFORMED;
        if (ok) PASS(); else FAIL("a damaged envelope was not refused");
    }
}

/* ── 4. find ─────────────────────────────────────────────────────── */

static size_t frame_with(uint8_t *buf, size_t cap, int qa_count, int qa_as_text) {
    cbor_encoder_t enc;
    cbor_encoder_init(&enc, buf, cap);
    cbor_encode_map(&enc, 4 + (size_t)qa_count);
    cbor_encode_cstr(&enc, "t");   cbor_encode_uint(&enc, 1);
    cbor_encode_cstr(&enc, "y");   cbor_encode_cstr(&enc, "q");
    cbor_encode_cstr(&enc, "q");   cbor_encode_cstr(&enc, "dnac_utxo");
    for (int i = 0; i < qa_count; i++) {
        cbor_encode_cstr(&enc, "qa");
        if (qa_as_text) cbor_encode_cstr(&enc, "not bytes");
        else cbor_encode_bstr(&enc, g_env, g_env_len);
    }
    cbor_encode_cstr(&enc, "a");   cbor_encode_map(&enc, 0);
    return cbor_encoder_len(&enc);
}

static void test_find(void) {
    TEST("find: qa beside a; absent -> 1; twice / text / not a map -> -1");
    uint8_t o[64];
    memset(o, 0x33, sizeof(o));
    if (build("dnac_utxo", o, g_t) != 0) { FAIL("build"); return; }
    static uint8_t buf[NODUS_OQ_ENV_MAX + 256];
    const uint8_t *env = NULL;
    size_t el = 0, n;
    int ok = 1;
    n = frame_with(buf, sizeof(buf), 1, 0);
    ok = ok && n > 0 && nodus_oq_find(buf, n, &env, &el) == 0 && el == g_env_len &&
         env != NULL && memcmp(env, g_env, g_env_len) == 0;
    n = frame_with(buf, sizeof(buf), 0, 0);
    ok = ok && nodus_oq_find(buf, n, &env, &el) == 1 && env == NULL && el == 0;
    n = frame_with(buf, sizeof(buf), 2, 0);
    ok = ok && nodus_oq_find(buf, n, &env, &el) == -1;
    n = frame_with(buf, sizeof(buf), 1, 1);
    ok = ok && nodus_oq_find(buf, n, &env, &el) == -1;
    {
        uint8_t arr[2] = { 0x81, 0x01 };     /* an array, not a map */
        ok = ok && nodus_oq_find(arr, sizeof(arr), &env, &el) == -1;
        ok = ok && nodus_oq_find(NULL, 3, &env, &el) == -1;
    }
    if (ok) PASS(); else FAIL("qa lookup in a T2 frame");
}

/* ── 5. o per method ─────────────────────────────────────────────── */

static void hex64(const uint8_t raw[64], char out[129]) {
    static const char d[] = "0123456789abcdef";
    for (int i = 0; i < 64; i++) {
        out[2 * i] = d[raw[i] >> 4];
        out[2 * i + 1] = d[raw[i] & 15];
    }
    out[128] = '\0';
}

static void test_o_per_method(void) {
    uint8_t fp_a[64], fp_b[64], got[64];

    TEST("o: utxo / addr_history — the hex owner must equal the signed o");
    qgp_sha3_512(g_owner.pk.bytes, NODUS_OQ_PK_LEN, fp_a);
    qgp_sha3_512(g_other.pk.bytes, NODUS_OQ_PK_LEN, fp_b);
    {
        char hex_a[129], hex_b[129];
        hex64(fp_a, hex_a);
        hex64(fp_b, hex_b);
        int ok = nodus_witness_owner_hex_to_raw(hex_a, 128, got) == 0 &&
                 nodus_oq_subject_ok(fp_a, got) &&
                 nodus_witness_owner_hex_to_raw(hex_b, 128, got) == 0 &&
                 !nodus_oq_subject_ok(fp_a, got);
        /* a one-bit difference anywhere is a mismatch */
        uint8_t nearby[64];
        memcpy(nearby, fp_a, 64);
        nearby[63] ^= 1;
        ok = ok && !nodus_oq_subject_ok(fp_a, nearby) && !nodus_oq_subject_ok(NULL, nearby);
        if (ok) PASS(); else FAIL("owner subject comparison");
    }

    TEST("o: delegations — SHA3-512(pubkey); zero / short pubkey refused");
    {
        uint8_t zero[NODUS_OQ_PK_LEN];
        memset(zero, 0, sizeof(zero));
        int ok = nodus_oq_delegations_subject(g_owner.pk.bytes, NODUS_OQ_PK_LEN, got) == 0 &&
                 memcmp(got, fp_a, 64) == 0 &&
                 nodus_oq_subject_ok(fp_a, got) &&
                 nodus_oq_delegations_subject(g_other.pk.bytes, NODUS_OQ_PK_LEN, got) == 0 &&
                 !nodus_oq_subject_ok(fp_a, got) &&
                 nodus_oq_delegations_subject(zero, NODUS_OQ_PK_LEN, got) == -1 &&
                 nodus_oq_delegations_subject(g_owner.pk.bytes, NODUS_OQ_PK_LEN - 1, got) == -1 &&
                 nodus_oq_delegations_subject(NULL, NODUS_OQ_PK_LEN, got) == -1;
        if (ok) PASS(); else FAIL("delegations subject");
    }

    TEST("o: msig — vault address == o, then the G8.1 member rule with the qa key");
    {
        nodus_identity_t k[3];
        const nodus_identity_t *ord[3];
        uint8_t keys[3 * NODUS_OQ_PK_LEN];
        uint8_t desc[DNA_MSIG_MAX_DESC_LEN], vault[64];
        size_t dlen = 0;
        int ok = 1;
        for (int i = 0; i < 3; i++) ok = ok && nodus_identity_generate(&k[i]) == 0;
        for (int i = 0; i < 3; i++) ord[i] = &k[i];
        /* strictly ascending by key bytes, as the descriptor requires */
        for (int i = 0; i < 3; i++)
            for (int j = i + 1; j < 3; j++)
                if (memcmp(ord[j]->pk.bytes, ord[i]->pk.bytes, NODUS_OQ_PK_LEN) < 0) {
                    const nodus_identity_t *tmp = ord[i];
                    ord[i] = ord[j];
                    ord[j] = tmp;
                }
        for (int i = 0; i < 3; i++)
            memcpy(keys + (size_t)i * NODUS_OQ_PK_LEN, ord[i]->pk.bytes, NODUS_OQ_PK_LEN);
        ok = ok && dna_msig_desc_encode(2, 3, keys, desc, sizeof(desc), &dlen) == 0 &&
             dna_msig_address(desc, dlen, vault) == 0;
        if (!ok) { FAIL("descriptor"); return; }
        uint8_t zero_pk[NODUS_OQ_PK_LEN];
        memset(zero_pk, 0, sizeof(zero_pk));
        uint8_t wrong_vault[64];
        memcpy(wrong_vault, vault, 64);
        wrong_vault[0] ^= 1;
        /* a member with the right vault passes; the same member with a wrong
         * vault address, a non-member key, and a zero key do not */
        ok = nodus_witness_msig_member_ok(ord[1]->pk.bytes, vault, desc, dlen) &&
             nodus_oq_subject_ok(vault, vault) &&
             !nodus_oq_subject_ok(vault, wrong_vault) &&
             !nodus_witness_msig_member_ok(ord[1]->pk.bytes, wrong_vault, desc, dlen) &&
             !nodus_witness_msig_member_ok(g_other.pk.bytes, vault, desc, dlen) &&
             !nodus_witness_msig_member_ok(zero_pk, vault, desc, dlen) &&
             !nodus_witness_msig_member_ok(NULL, vault, desc, dlen);
        for (int i = 0; i < 3; i++) nodus_identity_clear(&k[i]);
        if (ok) PASS(); else FAIL("msig membership with the qa key");
    }
}

int main(void) {
    printf("test_owner_query (DHT v2 package 3d, qa):\n");
    if (nodus_identity_generate(&g_owner) != 0 || nodus_identity_generate(&g_other) != 0) {
        printf("  identity generation FAILED\n");
        return 1;
    }
    for (int i = 0; i < 32; i++) g_chain[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 64; i++) {
        g_t[i] = (uint8_t)(0x10 + i);
        g_t2[i] = (uint8_t)(0x90 ^ i);
    }

    test_accept();
    test_payload();
    test_rejects();
    test_find();
    test_o_per_method();

    nodus_identity_clear(&g_owner);
    nodus_identity_clear(&g_other);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed ? 1 : 0;
}
