/**
 * Nodus Connect thin core — pure classifier tests (package NC-2).
 *
 * What it proves (no network, no clock in any decision under test):
 *   C1-C9  nc_classify_one maps every client answer to the documented
 *          outcome (design rev 5 §1.4 R0, §6.4 F1): 0 + good value -> FOUND;
 *          NOT_FOUND -> EMPTY; TIMEOUT / PROTOCOL_ERROR (undecodable, F1) /
 *          -1 / a node error -> UNREADABLE with the matching reason; a value
 *          with a broken DHT signature, signed for another key, or owned by
 *          someone other than the expected writer -> UNREADABLE.
 *   A1-A5  nc_classify_all: accepted values kept in reply order and the
 *          answer is PARTIAL (F5); no item at all -> EMPTY; only rejected
 *          or undecodable items -> UNREADABLE (never EMPTY); an error ->
 *          UNREADABLE.
 *   S1-S7  nc_servers_parse: the valid list, list order kept, a pinned
 *          validator without address, an unknown kind skipped, and the
 *          refusals (format, version, duplicate pin, no endpoint, bad IP).
 *   R1-R5  nc_salt_choose: the native reconcile rule (dht_salt_agreement.c
 *          salt_agreement_verify) — equal, lower-hash wins, DHT only, local
 *          only (republish wanted), all-zero local = unset.
 *
 * What it requires: the native build of web-wallet/connect/tests (see
 * CMakeLists.txt); no environment, no port.
 * What it leaves behind: nothing.
 * How it can lie: the values are built by nodus_value_create/sign in the
 * test — a mistake shared by that code and nodus_value_verify would pass
 * here; the fault-matrix test drives the same classifier through a real
 * client.
 */

#include "nc_core.h"
#include "core/nodus_value.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int passed, failed;
#define CHECK(cond, name) do {                                        \
    if (cond) { passed++; printf("  PASS %s\n", name); }              \
    else { failed++; printf("  FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); } \
} while (0)

static nodus_identity_t *g_a, *g_b;

static nodus_value_t *make_value(const nodus_identity_t *id,
                                 const nodus_key_t *key, int corrupt) {
    nodus_value_t *v = NULL;
    if (nodus_value_create(key, (const uint8_t *)"data", 4,
                           NODUS_VALUE_EPHEMERAL, 60, 1, 1, &id->pk, &v) != 0 ||
        nodus_value_sign(v, &id->sk) != 0)
        return NULL;
    if (corrupt) v->signature.bytes[10] ^= 0x01;
    return v;
}

static void test_one(void) {
    nodus_key_t key, other;
    memset(key.bytes, 0x11, sizeof(key.bytes));
    memset(other.bytes, 0x22, sizeof(other.bytes));
    nc_read_t r;

    nc_classify_one(0, make_value(g_a, &key, 0), &key, &g_a->node_id, &r);
    CHECK(r.outcome == NC_FOUND && r.value, "C1 good value, expected owner -> FOUND");
    nc_read_clear(&r);

    nc_classify_one(0, make_value(g_a, &key, 0), &key, NULL, &r);
    CHECK(r.outcome == NC_FOUND, "C2 good value, any owner -> FOUND");
    nc_read_clear(&r);

    nc_classify_one(NODUS_ERR_NOT_FOUND, NULL, &key, &g_a->node_id, &r);
    CHECK(r.outcome == NC_EMPTY, "C3 NOT_FOUND -> EMPTY");

    nc_classify_one(NODUS_ERR_TIMEOUT, NULL, &key, NULL, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_TIMEOUT, "C4 TIMEOUT -> UNREADABLE(timeout)");

    nc_classify_one(NODUS_ERR_PROTOCOL_ERROR, NULL, &key, NULL, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_UNDECODABLE,
          "C5 PROTOCOL_ERROR (undecodable, F1) -> UNREADABLE, never EMPTY");

    nc_classify_one(-1, NULL, &key, NULL, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_NOT_CONNECTED, "C6 -1 -> UNREADABLE(not_connected)");

    nc_classify_one(NODUS_ERR_RATE_LIMITED, NULL, &key, NULL, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_NODE_ERROR, "C7 node error -> UNREADABLE(node_error)");

    nc_classify_one(0, make_value(g_a, &key, 1), &key, &g_a->node_id, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_BAD_SIGNATURE && !r.value,
          "C8 bad DHT signature -> UNREADABLE(bad_signature)");

    nc_classify_one(0, make_value(g_b, &key, 0), &key, &g_a->node_id, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_WRONG_OWNER,
          "C9 another writer -> UNREADABLE(wrong_owner)");

    nc_classify_one(0, make_value(g_a, &other, 0), &key, &g_a->node_id, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_WRONG_KEY,
          "C10 value signed for another key -> UNREADABLE(wrong_key)");
}

static void test_all(void) {
    nodus_key_t key;
    memset(key.bytes, 0x11, sizeof(key.bytes));
    nc_read_all_t r;
    nodus_key_t owners[1] = { g_a->node_id };

    nodus_value_t **v = calloc(3, sizeof(*v));
    v[0] = make_value(g_b, &key, 0);          /* wrong owner */
    v[1] = make_value(g_a, &key, 0);          /* ok          */
    v[2] = make_value(g_a, &key, 1);          /* bad sig     */
    nc_classify_all(0, v, 3, 1, &key, owners, 1, &r);
    CHECK(r.outcome == NC_FOUND && r.count == 1 && r.partial &&
          r.wrong_owner == 1 && r.bad_sig == 1 && r.undecodable == 1,
          "A1 mixed answer -> FOUND, partial, counters");
    nc_read_all_clear(&r);

    nc_classify_all(0, NULL, 0, 0, &key, owners, 1, &r);
    CHECK(r.outcome == NC_EMPTY, "A2 no item -> EMPTY");

    nc_classify_all(0, NULL, 0, 2, &key, owners, 1, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_UNDECODABLE,
          "A3 only undecodable items -> UNREADABLE, never EMPTY");

    v = calloc(1, sizeof(*v));
    v[0] = make_value(g_b, &key, 0);
    nc_classify_all(0, v, 1, 0, &key, owners, 1, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_WRONG_OWNER,
          "A4 only rejected items -> UNREADABLE");

    nc_classify_all(NODUS_ERR_TIMEOUT, NULL, 0, 0, &key, owners, 1, &r);
    CHECK(r.outcome == NC_UNREADABLE && r.why == NC_WHY_TIMEOUT, "A5 timeout -> UNREADABLE");
}

static const char *PIN_A =
    "03499d1fae35f9e9aaf60a1c3f18d8c7d1ffa49f2c65bd4b6a531bdf8ef92c21c90bf5e64f29fb0b9f689ac20e7dc9df418784c788ffc43c735c9b38253038e0";
static const char *PIN_B =
    "fd429639366cbc41d98db7603d51166ed5542d2d161cf69ff1ab6dbe80176197dca892177f95cdb4757073531588bf63c7d3b91f6f016e0035272068de74b35c";

static void test_servers(void) {
    char json[2048], why[128];
    nc_servers_t s;

    snprintf(json, sizeof(json),
             "{\"format\":\"nodus-connect-servers\",\"version\":1,\"entries\":["
             "{\"kind\":\"validator-checkpoint\",\"pin\":\"%s\",\"host\":\"10.0.0.2\",\"port\":443},"
             "{\"kind\":\"dht-node\",\"pin\":\"%s\",\"host\":\"10.0.0.9\",\"port\":443},"
             "{\"kind\":\"validator-checkpoint\",\"pin\":\"%s\"}]}", PIN_A, PIN_B, PIN_B);
    int rc = nc_servers_parse(json, &s, why, sizeof(why));
    CHECK(rc == 0 && s.n_endpoints == 1 && s.n_pins == 2 && s.skipped_kinds == 1 &&
          strcmp(s.endpoints[0].ip, "10.0.0.2") == 0 && s.endpoints[0].port == 443,
          "S1 valid list: endpoint, address-less pin, unknown kind skipped");

    snprintf(json, sizeof(json),
             "{\"format\":\"nodus-connect-servers\",\"version\":1,\"entries\":["
             "{\"kind\":\"validator-checkpoint\",\"pin\":\"%s\",\"host\":\"10.0.0.3\",\"port\":443},"
             "{\"kind\":\"validator-checkpoint\",\"pin\":\"%s\",\"host\":\"10.0.0.2\",\"port\":443}]}",
             PIN_A, PIN_B);
    rc = nc_servers_parse(json, &s, why, sizeof(why));
    CHECK(rc == 0 && s.n_endpoints == 2 && strcmp(s.endpoints[0].ip, "10.0.0.3") == 0,
          "S2 list order kept (D8)");

    CHECK(nc_servers_parse("{\"format\":\"x\",\"version\":1,\"entries\":[]}", &s, why, sizeof(why)) == -1,
          "S3 unknown format refused");
    CHECK(nc_servers_parse("{\"format\":\"nodus-connect-servers\",\"version\":2,\"entries\":[]}", &s, why, sizeof(why)) == -1,
          "S4 unknown version refused");
    snprintf(json, sizeof(json),
             "{\"format\":\"nodus-connect-servers\",\"version\":1,\"entries\":["
             "{\"kind\":\"validator-checkpoint\",\"pin\":\"%s\",\"host\":\"10.0.0.2\",\"port\":443},"
             "{\"kind\":\"validator-checkpoint\",\"pin\":\"%s\"}]}", PIN_A, PIN_A);
    CHECK(nc_servers_parse(json, &s, why, sizeof(why)) == -1, "S5 duplicate pin refused");
    snprintf(json, sizeof(json),
             "{\"format\":\"nodus-connect-servers\",\"version\":1,\"entries\":["
             "{\"kind\":\"validator-checkpoint\",\"pin\":\"%s\"}]}", PIN_A);
    CHECK(nc_servers_parse(json, &s, why, sizeof(why)) == -1, "S6 no endpoint = connects nowhere, refused");
    snprintf(json, sizeof(json),
             "{\"format\":\"nodus-connect-servers\",\"version\":1,\"entries\":["
             "{\"kind\":\"validator-checkpoint\",\"pin\":\"%s\",\"host\":\"10.0.0.256\",\"port\":443}]}", PIN_A);
    CHECK(nc_servers_parse(json, &s, why, sizeof(why)) == -1, "S7 invalid IPv4 refused");
}

static void test_salt_choice(void) {
    uint8_t a[NC_SALT_LEN], b[NC_SALT_LEN], c[NC_SALT_LEN], z[NC_SALT_LEN];
    memset(a, 0xaa, sizeof(a));
    memset(b, 0xbb, sizeof(b));
    memset(z, 0, sizeof(z));
    bool rep = false;
    uint8_t ha[64], hb[64];
    qgp_sha3_512(a, NC_SALT_LEN, ha);
    qgp_sha3_512(b, NC_SALT_LEN, hb);
    const uint8_t *lower = memcmp(ha, hb, 64) <= 0 ? a : b;

    CHECK(nc_salt_choose(a, a, c, &rep) == NC_SALT_KEEP_LOCAL && !rep &&
          memcmp(c, a, NC_SALT_LEN) == 0, "R1 equal -> keep, no republish");
    nc_salt_choice_t ch = nc_salt_choose(a, b, c, &rep);
    CHECK(rep && memcmp(c, lower, NC_SALT_LEN) == 0 &&
          ch == (lower == a ? NC_SALT_KEEP_LOCAL : NC_SALT_TAKE_DHT),
          "R2 differ -> lower SHA3-512 wins");
    CHECK(nc_salt_choose(NULL, b, c, &rep) == NC_SALT_TAKE_DHT && !rep &&
          memcmp(c, b, NC_SALT_LEN) == 0, "R3 DHT only -> take DHT");
    CHECK(nc_salt_choose(a, NULL, c, &rep) == NC_SALT_KEEP_LOCAL && rep,
          "R4 local only -> keep, republish wanted (web cannot)");
    CHECK(nc_salt_choose(z, NULL, c, &rep) == NC_SALT_NONE, "R5 all-zero local = unset");
}

int main(void) {
    printf("=== Nodus Connect: pure classifier tests ===\n");
    g_a = calloc(1, sizeof(*g_a));
    g_b = calloc(1, sizeof(*g_b));
    if (!g_a || !g_b || nodus_identity_generate(g_a) != 0 ||
        nodus_identity_generate(g_b) != 0) {
        printf("FATAL: identities\n");
        return 1;
    }
    test_one();
    test_all();
    test_servers();
    test_salt_choice();
    nodus_identity_clear(g_a);
    nodus_identity_clear(g_b);
    free(g_a);
    free(g_b);
    printf("=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed ? 1 : 0;
}
