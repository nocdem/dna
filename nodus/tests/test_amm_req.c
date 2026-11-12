/**
 * test_amm_req.c -- the swap bot's signed-request verification (amm_req.c).
 *
 * Governing text: docs/plans/2026-11-08-swap-bot-plan.nodus1.md (revision 8)
 * section 6 (6.1, 6.2, 6.4.1 - 6.4.4, 6.4.6), section 19 `test_amm_req`,
 * section 22 question 12 (first choices); givens items 13, 16, 30, 57, 71,
 * 72, 73, 77.
 *
 * WHAT IT PROVES
 *   K1  the EIP-712 known answer of the reference: the `Mail` example of
 *       /home/nocdem/refs/eips/eip-712.md:178-192. Its domain separator, its
 *       struct hash and its digest are composed here BY HAND from keccak256
 *       (the encodeType strings and the encodeData rules of eip-712.md:84-104,
 *       not through amm_req's two fixed types), then the reference's own
 *       signature (eip-712.md:192, last byte 0x1c = 28) is run through
 *       amm_req_eth_recover and must give the address the reference passes as
 *       the signer (eip-712.md:183, 0xCD2a3d9F...D826). The digest is also
 *       checked against ethers 6.17.0 TypedDataEncoder.hash (see VECTORS).
 *   K2  the two typed digests of the plan (UsdtToNodusRequest,
 *       LiquidityAddRequest, plan 6.4.3 / 6.4.6) and the domain separator
 *       EIP712Domain(string name,uint256 chainId) equal the values ethers
 *       6.17.0 TypedDataEncoder produces, for chain id 1 and 11155111
 *       (Sepolia, givens item 77): the library the extension signs with
 *       (web-wallet/extension/src/background/keyring.js:33-41).
 *   T   USDT -> NODUS: the ethers signature of a request verifies and gives
 *       the typed fields; refused: a wrong signer, a chain id other than the
 *       setting (the Sepolia signature under chain id 1 and the mainnet one
 *       under 11155111), a last byte other than 27 / 28 (0, 1, 26, 29, 0x25
 *       = a v that carries a chain id, 0x26, 0xff; 28 on a signature made
 *       with 27 recovers another signer), r or s of 0 or not
 *       below the curve order, a destination that is not 128 lowercase hex,
 *       an uppercase or short or un-prefixed sender, a decimal with a leading
 *       zero / a sign / a letter / above 2^64 - 1; the high-s twin of a valid
 *       signature is accepted (as ecrecover accepts it, amm_req.h) and its
 *       number is then refused as a reuse.
 *   N   NODUS -> USDT text (6.4.4), liquidity add (6.4.6) and withdraw: a
 *       valid text of each kind verifies with nodus_verify_site_message over
 *       `expected_origin`; each kind built at its maximum length is exactly
 *       563 / 574 / 375 bytes (plan 6.4.2) and verifies; ONE refusal per
 *       strict rule of 6.4.2 -- every refused text is signed validly by its
 *       key, so the refusal can only be the format rule, never the signature
 *       (upper-case hex, a leading zero, a missing and an extra fraction
 *       digit, a wrong unit word, CR, tab, a trailing LF, a trailing space,
 *       two spaces and no space after a colon, a reordered / missing /
 *       repeated / unknown key, an empty line, a raw value above 2^64 - 1 for
 *       both amounts and the request number, basis points 0 and 10001, a
 *       non-ASCII byte, a NUL, a text above 574 bytes, a wrong title, a short
 *       address); a `Chain ID` other than the node's is AMM_REQ_CHAIN; a
 *       Nodus address that is not SHA3-512(public key) is AMM_REQ_ADDRESS;
 *       the signature checked under another origin, under the origin with a
 *       trailing slash, by another key, with a flipped byte is
 *       AMM_REQ_SIGNATURE.
 *   L   liquidity add pair: both halves verify and agree; refused as a pair
 *       when the USDT amount, the NODUS amount, the request number, the
 *       Ethereum address or the Nodus address differs between the halves
 *       (each half valid by itself).
 *   R   request numbers: a number accepted by amm_journal_approve is refused
 *       as AMM_REQ_REUSED for the same address after the journal is closed
 *       and reopened (plan 19 "after restart"), another number and another
 *       address are not; per kind: USDT -> NODUS (Ethereum address), NODUS ->
 *       USDT and withdraw (Nodus address), add (either of the two addresses).
 *   S   the settings of this package take effect: eth_chain_id and
 *       eip712_name change the domain (the same signature is refused under
 *       another name), approval_valid_seconds / commission are not read
 *       here (test_amm_cfg covers their loading).
 *
 * VECTORS. The typed vectors K2 / T were produced once with ethers 6.17.0
 * (/opt/dna/web-wallet/node_modules/ethers, package.json "version": "6.17.0")
 * from the private key 0x11 repeated 32 times (address
 * 0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a), domain {name: "Nodus Swap",
 * chainId: 1 | 11155111}, with `TypedDataEncoder.hashDomain`, `.hash` and
 * `Wallet.signTypedData`; messages:
 *   UsdtToNodusRequest { sender: <address>, destination: "ab" x 64,
 *     amount: "50000000", minimumToReceive: "490000000000",
 *     requestNumber: "9007199254740993" }  (a second one with "10")
 *   LiquidityAddRequest { ethereumAddress: <address>, nodusAddress: "ab" x 64,
 *     usdtAmount: "30000000", nodusAmount: "300000000000", requestNumber: "77" }
 * and the Mail example with ethers `TypedDataEncoder.hash` / `verifyTypedData`
 * (the reference's signature recovers to 0xCD2a3d9F...D826 there too). The
 * pair and refusal tests sign at run time with libsecp256k1 (same key) over
 * digests that K2 pins to ethers.
 *
 * WHAT IT REQUIRES: a default build; random ML-DSA-87 identities generated at
 *   run time (key generation randomness is allowed); one mkdtemp directory
 *   under /tmp for the journals, removed at the end; no network.
 * LEAVES BEHIND: nothing.
 * HOW IT CAN LIE
 *   - The Nodus-key side is self-consistent only: the texts are signed with
 *     nodus_sign_site_message and verified with nodus_verify_site_message, the
 *     same nodus_sign.c on both sides, as the vectors of
 *     web-wallet/crypto/nodus-send-native-vector.c:913-919 are (plan section
 *     19; CLAUDE.md:127 "A C/Rust byte match of the same invented spec proves
 *     self-consistency only"). No independent ML-DSA-87 check is named by the
 *     plan (OPEN, plan section 19). The text layouts themselves come from the
 *     plan's agreed draft, not from an external reference.
 *   - The typed side IS independent for the digests (ethers, K1/K2), but the
 *     27/28 and r,s-range rules are the plan's reading of the ecrecover port;
 *     the high-s acceptance is pinned here as that reading.
 *   - The curve order N below is copied from shared/evm/evm_precompile.c:
 *     138-143 (execution-specs elliptic_curve.py SECP256K1N), the same
 *     constant amm_req.c carries for its explicit 1..N-1 range check (the
 *     port's, evm_precompile.c:166-171); a typo shared by both would make the
 *     r,s-range cases test a wrong number. The high-s acceptance is pinned by
 *     the high-s twin case below, not by a reading of the libsecp256k1 source.
 *   - Refusal cases build the bad text by editing one place of the canonical
 *     text; a case that no longer edits (the pattern is absent) fails loudly
 *     (mutate() checks).
 */
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crypto/hash/keccak256.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/nodus_identity.h"
#include "crypto/nodus_sign.h"
#include "amm_req.h"
#include "nodus_log_shim.h"
#include <sys/stat.h>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, what)                                                    \
    do {                                                                     \
        g_checks++;                                                          \
        if (cond) { printf("  ok    %s\n", what); }                          \
        else { printf("  FAIL  %s  (line %d)\n", what, __LINE__); g_failures++; } \
    } while (0)

/* ── hex helpers ──────────────────────────────────────────────────────── */

static int hv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* `n` bytes from hex text (an optional 0x prefix is skipped). */
static void unhex(const char *s, uint8_t *out, size_t n) {
    if (s[0] == '0' && s[1] == 'x') s += 2;
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)((hv(s[2 * i]) << 4) | hv(s[2 * i + 1]));
}

static const char *hexof(const uint8_t *b, size_t n) {
    static char ring[8][300];
    static unsigned ri = 0;
    static const char D[] = "0123456789abcdef";
    char *o = ring[ri++ % 8];
    for (size_t i = 0; i < n && 2 * i + 2 < 300; i++) {
        o[2 * i] = D[b[i] >> 4];
        o[2 * i + 1] = D[b[i] & 15];
    }
    o[2 * n] = '\0';
    return o;
}

/* b (n bytes) equals the hex text, in either letter case, an optional 0x
 * prefix skipped (the reference writes the Mail signer in mixed case). */
static int eq_hex(const uint8_t *b, size_t n, const char *hex) {
    if (hex[0] == '0' && hex[1] == 'x') hex += 2;
    if (strlen(hex) != 2 * n) return 0;
    const char *mine = hexof(b, n);
    for (size_t i = 0; i < 2 * n; i++)
        if (hv(mine[i]) != hv(hex[i])) return 0;
    return 1;
}

/* ── the vectors (see VECTORS in the header) ──────────────────────────── */

#define V_ADDR  "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
#define V_DEST  "abababababababababababababababababababababababababababababababab" \
                "abababababababababababababababababababababababababababababababab"

#define V_DOMSEP_1        "0x88daa24b069a9b2bbeeafa21d8eabf5651cdd3b45e05025a345bb3f66241ea17"
#define V_HASH_U_1        "0x2a7de31ab4d8d0656ac320a6c94943ce66d5e7561fb43d6d478c5863a0fc37a0"
#define V_SIG_U_1         "0x238cd0b7affcf973eb70ff72c13da7924bd8c9287baff5bda99fdb6f90f37c62146ae5d4857ed7124c989ab06a8d9f0ffd7b512b5692c0c182ecc40949c3dfd51b"
#define V_HASH_L_1        "0xc342b49f92787538344fd062d55dc85d6e92c01d30aab32fabb009ab5228e77b"
#define V_SIG_L_1         "0x18a6fd63663f4a228f59284b1297da86d7c44b76ba0dcbeff48cb079d1319cb563d88fe6fbac10bff986ecae22b1f36908be54ee62374789b962b862a52033131c"
#define V_DOMSEP_S        "0x2520ce2266d9b718d5f7909e912a379e257dfbeb5cdff620e680d70cb7f27f85"
#define V_HASH_U_S        "0x7a55d0f3237e26a873e3ec6f4fa676d48ea5e10dd546e5aecf32a7d851f0ac57"
#define V_SIG_U_S         "0x182793871300c8a6e439b75a1750b732d57004a297e5abf737d1cdffa77d114d67c0a3a6fe0eab62d583f0573e0d3440614c7e8f530ef2e55271e028143ed4131b"
#define V_HASH_L_S        "0x18e75fa1af45965422addbf1d24d001fc4759a62555cf27421e13db60a3b2c73"
#define V_SIG_L_S         "0x88c31b4f2d1e17613db5dc5cd834e9cfea5fe685a537386d29d2d41afa2f58136c9fec6e59f5f7ed22c25008c8921f4871ac4ac2d0fa3718303368b7a8d2e8a41b"
/* the same UsdtToNodusRequest with requestNumber "10", chain id 1 */
#define V_HASH_U_1_N10    "0xe80bd00afed30247c1bedf517d3af8cccb6e068502e08bfe0bfd0041933edc44"
#define V_SIG_U_1_N10     "0x4c62897a7532bcf94ead9cc35b2cf2a3125c3db908e52f25e40e507890acd2643bc9d2bb01ae3f4524ad35849f3f286586b2505d65a7fa547572025e494870d61b"

/* the Mail example (eip-712.md:178-192) */
#define MAIL_SIGNER_ADDR  "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"   /* :183 */
#define MAIL_SIG          "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c" /* :192 */
#define MAIL_DOMSEP       "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
#define MAIL_STRUCT       "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
#define MAIL_DIGEST       "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"

/* secp256k1 order N, shared/evm/evm_precompile.c:138-143 */
static const uint8_t ORDER_N[32] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
};

/* ── fixtures ─────────────────────────────────────────────────────────── */

#define GOOD_ORIGIN "https://swap.nodusnetwork.io"

static amm_cfg_t g_cfg;
static nodus_identity_t *g_id1, *g_id2;
static char g_addr1[129], g_addr2[129];      /* SHA3-512(public key), hex      */
static char g_chain_hex[65];
static char g_dir[64];
static int g_jn = 0;
static amm_journal_t *g_j;                   /* a journal with no markers      */
static const uint8_t TEST_SK[32] = {
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11
};

static void addr_of(const nodus_identity_t *id, char out[129]) {
    uint8_t raw[64];
    qgp_sha3_512(id->pk.bytes, NODUS_PK_BYTES, raw);
    memcpy(out, hexof(raw, 64), 129);
}

static nodus_identity_t *new_id(void) {
    nodus_identity_t *id = calloc(1, sizeof(*id));
    if (!id || nodus_identity_generate(id) != 0) {
        printf("FATAL: identity generation failed\n");
        exit(2);
    }
    return id;
}

static amm_journal_t *fresh_journal(void) {
    char path[160];
    snprintf(path, sizeof(path), "%s/j%d.db", g_dir, g_jn++);
    amm_journal_t *j = NULL;
    if (amm_journal_open(path, &j) != 0) {
        printf("FATAL: cannot open a journal\n");
        exit(2);
    }
    return j;
}

static amm_journal_t *reopen_journal(int n) {
    char path[160];
    snprintf(path, sizeof(path), "%s/j%d.db", g_dir, n);
    amm_journal_t *j = NULL;
    if (amm_journal_open(path, &j) != 0) {
        printf("FATAL: cannot reopen a journal\n");
        exit(2);
    }
    return j;
}

static void cleanup(void) {
    char p[200];
    for (int i = 0; i < g_jn; i++) {
        snprintf(p, sizeof(p), "%s/j%d.db", g_dir, i); unlink(p);
        snprintf(p, sizeof(p), "%s/j%d.db-wal", g_dir, i); unlink(p);
        snprintf(p, sizeof(p), "%s/j%d.db-shm", g_dir, i); unlink(p);
    }
    rmdir(g_dir);
}

/* Ethereum signature at run time, libsecp256k1 (the same call shape as
 * amm_eth_tx.c). */
static void eth_sign(const uint8_t digest[32], uint8_t sig[65]) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_ecdsa_recoverable_signature rs;
    int recid = 0;
    if (!ctx || !secp256k1_ecdsa_sign_recoverable(ctx, &rs, digest, TEST_SK, NULL, NULL) ||
        !secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig, &recid, &rs)) {
        printf("FATAL: secp256k1 signing failed\n");
        exit(2);
    }
    sig[64] = (uint8_t)(27 + recid);
    secp256k1_context_destroy(ctx);
}

/* ── typed requests ───────────────────────────────────────────────────── */

static amm_req_usdt_in_t usdt_in(const char *sender, const char *dest,
                                 const char *amount, const char *min,
                                 const char *reqno, const char *sig_hex) {
    amm_req_usdt_in_t in;
    memset(&in, 0, sizeof(in));
    in.sender = sender; in.destination = dest; in.amount = amount;
    in.minimum_to_receive = min; in.request_number = reqno;
    unhex(sig_hex, in.signature, 65);
    return in;
}

static amm_req_usdt_in_t vec_usdt(void) {
    return usdt_in(V_ADDR, V_DEST, "50000000", "490000000000", "9007199254740993",
                   V_SIG_U_1);
}

static int usdt_rc(const amm_req_usdt_in_t *in) {
    amm_req_usdt_t out;
    return amm_req_usdt_verify(&g_cfg, g_j, in, &out);
}

static void k1_mail(void) {
    printf("K1 EIP-712 known answer: the Mail example, composed by hand\n");
    uint8_t enc4[5 * 32], dom[32], from[32], to[32], mail[32], digest[32];
    memset(enc4, 0, sizeof(enc4));
    /* domain: EIP712Domain(string name,string version,uint256 chainId,address
     * verifyingContract), eip-712.md:113-125 */
    const char *dt = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
    keccak256((const uint8_t *)dt, strlen(dt), enc4);
    keccak256((const uint8_t *)"Ether Mail", 10, enc4 + 32);
    keccak256((const uint8_t *)"1", 1, enc4 + 64);
    enc4[96 + 31] = 1;                                        /* chainId 1 */
    memset(enc4 + 128 + 12, 0xcc, 20);                        /* 0xCccc...cC */
    keccak256(enc4, 5 * 32, dom);
    CHECK(eq_hex(dom, 32, MAIL_DOMSEP), "domain separator of the example");

    /* Person(string name,address wallet), Mail(Person from,Person to,string
     * contents)Person(string name,address wallet): eip-712.md:84-104 */
    const char *pt = "Person(string name,address wallet)";
    const char *mt = "Mail(Person from,Person to,string contents)Person(string name,address wallet)";
    uint8_t pe[3 * 32];
    memset(pe, 0, sizeof(pe));
    keccak256((const uint8_t *)pt, strlen(pt), pe);
    keccak256((const uint8_t *)"Cow", 3, pe + 32);
    unhex(MAIL_SIGNER_ADDR, pe + 64 + 12, 20);
    keccak256(pe, sizeof(pe), from);
    memset(pe, 0, sizeof(pe));
    keccak256((const uint8_t *)pt, strlen(pt), pe);
    keccak256((const uint8_t *)"Bob", 3, pe + 32);
    memset(pe + 64 + 12, 0xbb, 20);
    keccak256(pe, sizeof(pe), to);
    uint8_t me[4 * 32];
    keccak256((const uint8_t *)mt, strlen(mt), me);
    memcpy(me + 32, from, 32);
    memcpy(me + 64, to, 32);
    keccak256((const uint8_t *)"Hello, Bob!", 11, me + 96);
    keccak256(me, sizeof(me), mail);
    CHECK(eq_hex(mail, 32, MAIL_STRUCT), "hashStruct(Mail) of the example");

    CHECK(amm_req_eip712_digest(dom, mail, digest) == 0 &&
          eq_hex(digest, 32, MAIL_DIGEST), "digest keccak256(0x1901 || domain || struct)");
    uint8_t sig[65], addr[20];
    unhex(MAIL_SIG, sig, 65);
    CHECK(sig[64] == 0x1c, "the reference signature ends in 0x1c = 28 (eip-712.md:192)");
    CHECK(amm_req_eth_recover(digest, sig, addr) == 0 &&
          eq_hex(addr, 20, MAIL_SIGNER_ADDR),
          "the reference signature recovers to the signer the reference names");
    /* negative control: another digest gives another address or a refusal */
    uint8_t other[32];
    memcpy(other, digest, 32);
    other[0] ^= 1;
    CHECK(amm_req_eth_recover(other, sig, addr) != 0 ||
          !eq_hex(addr, 20, MAIL_SIGNER_ADDR), "a changed digest does not recover the signer");
}

static void k2_digests(void) {
    printf("K2 typed digests against ethers 6.17.0\n");
    uint8_t d[32];
    CHECK(amm_req_domain_separator("Nodus Swap", 1, d) == 0 && eq_hex(d, 32, V_DOMSEP_1),
          "domain separator, chain id 1");
    CHECK(amm_req_domain_separator("Nodus Swap", 11155111ULL, d) == 0 &&
          eq_hex(d, 32, V_DOMSEP_S), "domain separator, chain id 11155111");

    amm_req_usdt_t u;
    memset(&u, 0, sizeof(u));
    memcpy(u.sender, V_ADDR + 2, 41);
    memcpy(u.destination, V_DEST, 129);
    u.amount = 50000000ULL; u.minimum = 490000000000ULL;
    u.request_number = 9007199254740993ULL;
    CHECK(amm_req_usdt_digest("Nodus Swap", 1, &u, d) == 0 && eq_hex(d, 32, V_HASH_U_1),
          "UsdtToNodusRequest digest, chain id 1");
    CHECK(amm_req_usdt_digest("Nodus Swap", 11155111ULL, &u, d) == 0 &&
          eq_hex(d, 32, V_HASH_U_S), "UsdtToNodusRequest digest, chain id 11155111");
    u.request_number = 10;
    CHECK(amm_req_usdt_digest("Nodus Swap", 1, &u, d) == 0 && eq_hex(d, 32, V_HASH_U_1_N10),
          "UsdtToNodusRequest digest, request number 10");

    amm_req_liq_add_t l;
    memset(&l, 0, sizeof(l));
    memcpy(l.ethereum_address, V_ADDR + 2, 41);
    memcpy(l.nodus_address, V_DEST, 129);
    l.usdt_amount = 30000000ULL; l.nodus_amount = 300000000000ULL; l.request_number = 77;
    CHECK(amm_req_liq_add_digest("Nodus Swap", 1, &l, d) == 0 && eq_hex(d, 32, V_HASH_L_1),
          "LiquidityAddRequest digest, chain id 1");
    CHECK(amm_req_liq_add_digest("Nodus Swap", 11155111ULL, &l, d) == 0 &&
          eq_hex(d, 32, V_HASH_L_S), "LiquidityAddRequest digest, chain id 11155111");

    /* the ethers signatures recover to the key's address over these digests */
    uint8_t sig[65], a[20], dg[32];
    unhex(V_HASH_L_1, dg, 32);
    unhex(V_SIG_L_1, sig, 65);
    CHECK(amm_req_eth_recover(dg, sig, a) == 0 && eq_hex(a, 20, V_ADDR),
          "ethers LiquidityAddRequest signature recovers to the key's address");
    unhex(V_HASH_L_S, dg, 32);
    unhex(V_SIG_L_S, sig, 65);
    CHECK(amm_req_eth_recover(dg, sig, a) == 0 && eq_hex(a, 20, V_ADDR),
          "same, chain id 11155111");
}

static void t_typed(void) {
    printf("T USDT -> NODUS typed request\n");
    amm_req_usdt_in_t in = vec_usdt();
    amm_req_usdt_t out;
    CHECK(amm_req_usdt_verify(&g_cfg, g_j, &in, &out) == AMM_REQ_OK, "ethers-signed request verifies");
    CHECK(!strcmp(out.sender, V_ADDR + 2) && !strcmp(out.destination, V_DEST) &&
          out.amount == 50000000ULL && out.minimum == 490000000000ULL &&
          out.request_number == 9007199254740993ULL, "the typed fields are returned");
    /* 9007199254740993 = 0x0020000000000001 */
    CHECK(out.req_no[31] == 0x01 && out.req_no[30] == 0x00 && out.req_no[25] == 0x20 &&
          out.req_no[24] == 0x00 && out.req_no[23] == 0x00 && out.req_no[0] == 0,
          "request number big-endian in 32 bytes");

    /* chain id is a setting: Sepolia signature under chain id 1 is a wrong
     * signer; under 11155111 it verifies */
    amm_req_usdt_in_t sep = usdt_in(V_ADDR, V_DEST, "50000000", "490000000000",
                                    "9007199254740993", V_SIG_U_S);
    CHECK(usdt_rc(&sep) == AMM_REQ_SIGNATURE, "Sepolia signature under chain id 1 refused");
    amm_cfg_t sc = g_cfg;
    sc.eth_chain_id = 11155111ULL;
    CHECK(amm_req_usdt_verify(&sc, g_j, &sep, &out) == AMM_REQ_OK,
          "Sepolia signature under chain id 11155111 verifies (setting eth_chain_id)");
    CHECK(amm_req_usdt_verify(&sc, g_j, &in, &out) == AMM_REQ_SIGNATURE,
          "mainnet signature under chain id 11155111 refused");
    sc = g_cfg;
    strcpy(sc.eip712_name, "Nodus Swap2");
    CHECK(amm_req_usdt_verify(&sc, g_j, &in, &out) == AMM_REQ_SIGNATURE,
          "another domain name (setting eip712_name) refused");

    /* wrong signer: the sender field names another address */
    amm_req_usdt_in_t w = vec_usdt();
    w.sender = "0x29e7e376e7c213b7e7e7e46cc70a5dd086daff2a";
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, "sender is not the recovered signer: refused");
    /* a field changed after signing */
    w = vec_usdt(); w.amount = "50000001";
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, "amount changed after signing: refused");
    w = vec_usdt(); w.minimum_to_receive = "490000000001";
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, "minimum changed after signing: refused");
    w = vec_usdt(); w.request_number = "9007199254740994";
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, "request number changed after signing: refused");

    /* last byte */
    static const uint8_t bad_v[] = {0x00, 0x01, 26, 29, 0x25, 0x26, 0xff};
    for (size_t i = 0; i < sizeof(bad_v); i++) {
        char msg[80];
        w = vec_usdt(); w.signature[64] = bad_v[i];
        snprintf(msg, sizeof(msg), "last byte 0x%02x refused", bad_v[i]);
        CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, msg);
    }
    /* V_SIG_U_1 ends in 0x1b = 27; 28 is the other recovery id */
    CHECK(in.signature[64] == 27, "the vector's last byte is 27");
    w = vec_usdt(); w.signature[64] = 28;
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE,
          "last byte 28 where the signature is 27: the other recovery id, another signer, refused");

    /* r and s out of range */
    w = vec_usdt(); memset(w.signature + 32, 0, 32);
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, "s = 0 refused");
    w = vec_usdt(); memset(w.signature, 0, 32);
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, "r = 0 refused");
    w = vec_usdt(); memcpy(w.signature + 32, ORDER_N, 32);
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, "s = N refused");
    w = vec_usdt(); memcpy(w.signature, ORDER_N, 32);
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, "r = N refused");
    w = vec_usdt(); memset(w.signature + 32, 0xff, 32);
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE, "s = 2^256 - 1 refused");

    /* the high-s twin: s' = N - s, v' = 55 - v: ecrecover accepts it */
    {
        amm_req_usdt_in_t tw = vec_usdt();
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int d = (int)ORDER_N[i] - (int)in.signature[32 + i] - borrow;
            borrow = d < 0;
            tw.signature[32 + i] = (uint8_t)(d + (borrow ? 256 : 0));
        }
        tw.signature[64] = (uint8_t)(55 - in.signature[64]);
        CHECK(amm_req_usdt_verify(&g_cfg, g_j, &tw, &out) == AMM_REQ_OK,
              "the high-s twin of a valid signature is accepted (as ecrecover does)");
    }

    /* format rules of 6.4.3 */
    char dest127[130], dest129[131], destcap[130];
    memcpy(dest127, V_DEST, 127); dest127[127] = '\0';        /* one short */
    memcpy(dest129, V_DEST, 128); dest129[128] = 'a'; dest129[129] = '\0';  /* one long */
    memcpy(destcap, V_DEST, 129); destcap[0] = 'A';           /* one capital */
    const struct { const char *what; const char *sender, *dest, *amount, *min, *req; } bad[] = {
        {"sender in capitals", "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A", V_DEST, "50000000", "490000000000", "9007199254740993"},
        {"sender without 0x", "19e7e376e7c213b7e7e7e46cc70a5dd086daff2a", V_DEST, "50000000", "490000000000", "9007199254740993"},
        {"sender one digit short", "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2", V_DEST, "50000000", "490000000000", "9007199254740993"},
        {"sender with a non-hex digit", "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2g", V_DEST, "50000000", "490000000000", "9007199254740993"},
        {"destination 127 digits", V_ADDR, dest127, "50000000", "490000000000", "9007199254740993"},
        {"destination 129 digits", V_ADDR, dest129, "50000000", "490000000000", "9007199254740993"},
        {"destination with 0x", V_ADDR, "0x" V_DEST, "50000000", "490000000000", "9007199254740993"},
        {"destination in capitals", V_ADDR, destcap, "50000000", "490000000000", "9007199254740993"},
        {"amount with a leading zero", V_ADDR, V_DEST, "050000000", "490000000000", "9007199254740993"},
        {"amount with a sign", V_ADDR, V_DEST, "+50000000", "490000000000", "9007199254740993"},
        {"amount negative", V_ADDR, V_DEST, "-1", "490000000000", "9007199254740993"},
        {"amount with a letter", V_ADDR, V_DEST, "5e7", "490000000000", "9007199254740993"},
        {"amount in hex", V_ADDR, V_DEST, "0x10", "490000000000", "9007199254740993"},
        {"amount empty", V_ADDR, V_DEST, "", "490000000000", "9007199254740993"},
        {"amount with a point", V_ADDR, V_DEST, "50.000000", "490000000000", "9007199254740993"},
        {"amount 2^64", V_ADDR, V_DEST, "18446744073709551616", "490000000000", "9007199254740993"},
        {"amount 21 digits", V_ADDR, V_DEST, "100000000000000000000", "490000000000", "9007199254740993"},
        {"minimum 2^64", V_ADDR, V_DEST, "50000000", "18446744073709551616", "9007199254740993"},
        {"minimum with a leading zero", V_ADDR, V_DEST, "50000000", "00", "9007199254740993"},
        {"request number 2^64", V_ADDR, V_DEST, "50000000", "490000000000", "18446744073709551616"},
        {"request number with a leading zero", V_ADDR, V_DEST, "50000000", "490000000000", "09"},
        {"request number with a space", V_ADDR, V_DEST, "50000000", "490000000000", " 9"},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char msg[120];
        w = usdt_in(bad[i].sender, bad[i].dest, bad[i].amount, bad[i].min, bad[i].req, V_SIG_U_1);
        snprintf(msg, sizeof(msg), "%s refused as a format fault", bad[i].what);
        CHECK(usdt_rc(&w) == AMM_REQ_FORMAT, msg);
    }
    /* the bound itself is a valid format (signature then fails: another
     * signed message), zero is a valid decimal */
    w = usdt_in(V_ADDR, V_DEST, "18446744073709551615", "0", "0", V_SIG_U_1);
    CHECK(usdt_rc(&w) == AMM_REQ_SIGNATURE,
          "amount 2^64 - 1, minimum 0, request number 0 pass the format rules");
}

/* ── Nodus-key texts ──────────────────────────────────────────────────── */

typedef struct { char t[2048]; size_t n; } txt_t;

static txt_t nu_text(const char *sender, const char *dest, const char *amount,
                     const char *min, const char *tid, const char *chain,
                     const char *req) {
    txt_t x;
    int n = snprintf(x.t, sizeof(x.t),
                     "Nodus Swap: NODUS to USDT request\nSender: %s\nDestination: %s\n"
                     "Amount: %s\nMinimum To Receive: %s\nTransfer ID: %s\n"
                     "Chain ID: %s\nRequest Number: %s",
                     sender, dest, amount, min, tid, chain, req);
    x.n = (n > 0 && (size_t)n < sizeof(x.t)) ? (size_t)n : 0;
    return x;
}

static txt_t la_text(const char *eth, const char *nodus, const char *usdt,
                     const char *nds, const char *tid, const char *chain,
                     const char *req) {
    txt_t x;
    int n = snprintf(x.t, sizeof(x.t),
                     "Nodus Swap: liquidity add request\nEthereum Address: %s\n"
                     "Nodus Address: %s\nUSDT Amount: %s\nNODUS Amount: %s\n"
                     "Transfer ID: %s\nChain ID: %s\nRequest Number: %s",
                     eth, nodus, usdt, nds, tid, chain, req);
    x.n = (n > 0 && (size_t)n < sizeof(x.t)) ? (size_t)n : 0;
    return x;
}

static txt_t lw_text(const char *eth, const char *nodus, const char *bps,
                     const char *chain, const char *req) {
    txt_t x;
    int n = snprintf(x.t, sizeof(x.t),
                     "Nodus Swap: liquidity withdraw request\nEthereum Address: %s\n"
                     "Nodus Address: %s\nBasis Points: %s\nChain ID: %s\n"
                     "Request Number: %s",
                     eth, nodus, bps, chain, req);
    x.n = (n > 0 && (size_t)n < sizeof(x.t)) ? (size_t)n : 0;
    return x;
}

/* Replace the first `from` in the text by `to`; the pattern must exist. */
static txt_t mutate(txt_t x, const char *from, const char *to) {
    char *p = strstr(x.t, from);
    if (!p) {
        printf("  FAIL  mutate: pattern \"%s\" not found  (line %d)\n", from, __LINE__);
        g_failures++; g_checks++;
        return x;
    }
    txt_t y;
    size_t pre = (size_t)(p - x.t), fl = strlen(from), tl = strlen(to);
    memcpy(y.t, x.t, pre);
    memcpy(y.t + pre, to, tl);
    memcpy(y.t + pre + tl, p + fl, x.n - pre - fl);
    y.n = x.n - fl + tl;
    y.t[y.n] = '\0';
    return y;
}

static char TID[129], ETHD[43];

static txt_t good_nu(void) {
    return nu_text(g_addr1, ETHD, "500000.00000000 NODUS", "49.500000 USDT", TID,
                   g_chain_hex, "9007199254740993");
}
static txt_t good_la(void) {
    return la_text(ETHD, g_addr1, "30.000000 USDT", "3000.00000000 NODUS", TID,
                   g_chain_hex, "77");
}
static txt_t good_lw(void) {
    return lw_text(ETHD, g_addr1, "2500", g_chain_hex, "5");
}

static nodus_sig_t g_sig;

static void sign_with(const nodus_identity_t *id, const char *origin, const txt_t *x) {
    if (nodus_sign_site_message(&g_sig, (const uint8_t *)origin, strlen(origin),
                                (const uint8_t *)x->t, x->n, &id->sk) != 0) {
        printf("FATAL: nodus_sign_site_message failed\n");
        exit(2);
    }
}

/* Sign `x` validly by key 1 under the good origin, then verify as a kind. */
enum { K_NU, K_LA, K_LW };

static amm_req_nodus_in_t nin(const txt_t *x, const nodus_identity_t *pk_of) {
    amm_req_nodus_in_t in;
    in.text = (const uint8_t *)x->t; in.text_len = x->n;
    in.public_key = &pk_of->pk; in.signature = &g_sig;
    return in;
}

static int nu_rc(const txt_t *x) {
    amm_req_nodus_to_usdt_t o;
    sign_with(g_id1, GOOD_ORIGIN, x);
    amm_req_nodus_in_t in = nin(x, g_id1);
    return amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o);
}
static int lw_rc(const txt_t *x) {
    amm_req_liq_withdraw_t o;
    sign_with(g_id1, GOOD_ORIGIN, x);
    amm_req_nodus_in_t in = nin(x, g_id1);
    return amm_req_liquidity_withdraw_verify(&g_cfg, g_j, &in, &o);
}

/* The typed half for the add: signed at run time by the test key over the
 * digest of the given fields (digest pinned to ethers by K2). */
static amm_req_liq_eth_in_t la_eth(const char *eth, const char *nodus, const char *usdt,
                                   const char *nds, const char *req) {
    amm_req_liq_eth_in_t e;
    memset(&e, 0, sizeof(e));
    e.ethereum_address = eth; e.nodus_address = nodus; e.usdt_amount = usdt;
    e.nodus_amount = nds; e.request_number = req;
    amm_req_liq_add_t l;
    memset(&l, 0, sizeof(l));
    memcpy(l.ethereum_address, eth + 2, 41);
    memcpy(l.nodus_address, nodus, 129);
    l.usdt_amount = strtoull(usdt, NULL, 10);
    l.nodus_amount = strtoull(nds, NULL, 10);
    l.request_number = strtoull(req, NULL, 10);
    uint8_t d[32];
    amm_req_liq_add_digest(g_cfg.eip712_name, g_cfg.eth_chain_id, &l, d);
    eth_sign(d, e.signature);
    return e;
}

static int la_rc(const amm_req_liq_eth_in_t *e, const txt_t *x) {
    amm_req_liq_add_t o;
    sign_with(g_id1, GOOD_ORIGIN, x);
    amm_req_nodus_in_t in = nin(x, g_id1);
    return amm_req_liquidity_add_verify(&g_cfg, g_j, e, &in, &o);
}

static void n_valid(void) {
    printf("N valid texts and maximum lengths\n");
    txt_t x = good_nu();
    amm_req_nodus_to_usdt_t o;
    sign_with(g_id1, GOOD_ORIGIN, &x);
    amm_req_nodus_in_t in = nin(&x, g_id1);
    CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_OK,
          "NODUS -> USDT text verifies");
    CHECK(!strcmp(o.sender, g_addr1) && !strcmp(o.destination, ETHD + 2) &&
          o.amount == 50000000000000ULL && o.minimum == 49500000ULL &&
          !strcmp(o.transfer_id, TID) && o.request_number == 9007199254740993ULL &&
          o.req_no[31] == 0x01, "NODUS -> USDT fields: raw amounts, ids, number");

    txt_t l = good_la();
    amm_req_liq_eth_in_t e = la_eth(V_ADDR, g_addr1, "30000000", "300000000000", "77");
    /* the text names the Ethereum address in the lowercase 0x form */
    l = la_text(V_ADDR, g_addr1, "30.000000 USDT", "3000.00000000 NODUS", TID, g_chain_hex, "77");
    amm_req_liq_add_t lo;
    sign_with(g_id1, GOOD_ORIGIN, &l);
    in = nin(&l, g_id1);
    CHECK(amm_req_liquidity_add_verify(&g_cfg, g_j, &e, &in, &lo) == AMM_REQ_OK,
          "liquidity add: both halves verify and agree");
    CHECK(!strcmp(lo.ethereum_address, V_ADDR + 2) && !strcmp(lo.nodus_address, g_addr1) &&
          lo.usdt_amount == 30000000ULL && lo.nodus_amount == 300000000000ULL &&
          lo.request_number == 77 && !strcmp(lo.transfer_id, TID),
          "liquidity add fields");

    txt_t w = lw_text(V_ADDR, g_addr1, "2500", g_chain_hex, "5");
    amm_req_liq_withdraw_t wo;
    sign_with(g_id1, GOOD_ORIGIN, &w);
    in = nin(&w, g_id1);
    CHECK(amm_req_liquidity_withdraw_verify(&g_cfg, g_j, &in, &wo) == AMM_REQ_OK,
          "liquidity withdraw verifies");
    CHECK(!strcmp(wo.ethereum_address, V_ADDR + 2) && !strcmp(wo.nodus_address, g_addr1) &&
          wo.basis_points == 2500 && wo.request_number == 5, "withdraw fields");

    /* maximum lengths (plan 6.4.2): 563 / 574 / 375 */
    txt_t mn = nu_text(g_addr1, ETHD, "184467440737.09551615 NODUS", "18446744073709.551615 USDT",
                       TID, g_chain_hex, "18446744073709551615");
    CHECK(mn.n == 563, "NODUS -> USDT text at its bounds is 563 bytes");
    CHECK(nu_rc(&mn) == AMM_REQ_OK, "NODUS -> USDT at its maximum length verifies");
    amm_req_nodus_to_usdt_t mo;
    sign_with(g_id1, GOOD_ORIGIN, &mn);
    in = nin(&mn, g_id1);
    CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &mo) == AMM_REQ_OK &&
          mo.amount == UINT64_MAX && mo.minimum == UINT64_MAX &&
          mo.request_number == UINT64_MAX, "the three bounds read back as 2^64 - 1");

    txt_t ml = la_text(V_ADDR, g_addr1, "18446744073709.551615 USDT", "184467440737.09551615 NODUS",
                       TID, g_chain_hex, "18446744073709551615");
    CHECK(ml.n == 574, "liquidity add text at its bounds is 574 bytes");
    amm_req_liq_eth_in_t me = la_eth(V_ADDR, g_addr1, "18446744073709551615",
                                     "18446744073709551615", "18446744073709551615");
    CHECK(la_rc(&me, &ml) == AMM_REQ_OK, "liquidity add at its maximum length verifies");

    txt_t mw = lw_text(V_ADDR, g_addr1, "10000", g_chain_hex, "18446744073709551615");
    CHECK(mw.n == 375, "liquidity withdraw text at its bounds is 375 bytes");
    CHECK(lw_rc(&mw) == AMM_REQ_OK, "liquidity withdraw at its maximum length verifies");
    txt_t w1 = lw_text(V_ADDR, g_addr1, "1", g_chain_hex, "0");
    CHECK(lw_rc(&w1) == AMM_REQ_OK, "basis points 1 and request number 0 verify");
}

static void n_strict(void) {
    printf("N strict parsing: one refusal per rule of 6.4.2\n");
    txt_t g = good_nu();
    char msg[160];
#define REFUSE(label, tx)                                                    \
    do {                                                                     \
        txt_t t_ = (tx);                                                     \
        snprintf(msg, sizeof(msg), "%s refused as a format fault", label);   \
        CHECK(t_.n > 0 && nu_rc(&t_) == AMM_REQ_FORMAT, msg);                \
    } while (0)

    /* a control: the unedited text passes under the same helper */
    CHECK(nu_rc(&g) == AMM_REQ_OK, "control: the canonical text passes under the same helper");

    /* an upper-case hex digit: in the Ethereum address and in the transfer id */
    {
        txt_t t = g;
        char *p = strstr(t.t, "Destination: 0x") + 15;
        while (*p && !(*p >= 'a' && *p <= 'f')) p++;
        *p = (char)(*p - 'a' + 'A');
        REFUSE("upper-case hex in the Ethereum address", t);
        t = g;
        p = strstr(t.t, "Transfer ID: ") + 13;
        while (*p && !(*p >= 'a' && *p <= 'f')) p++;
        *p = (char)(*p - 'a' + 'A');
        REFUSE("upper-case hex in the transfer id", t);
        t = g;
        p = strstr(t.t, "Sender: ") + 8;
        while (*p && !(*p >= 'a' && *p <= 'f')) p++;
        *p = (char)(*p - 'a' + 'A');
        REFUSE("upper-case hex in the Nodus address", t);
    }
    REFUSE("Ethereum address without 0x", mutate(g, "Destination: 0x", "Destination: "));
    REFUSE("Ethereum address with 41 digits", mutate(g, "Destination: 0x", "Destination: 0x1"));
    REFUSE("a leading zero in the NODUS amount", mutate(g, "Amount: 500000.", "Amount: 0500000."));
    REFUSE("an empty integer part", mutate(g, "Amount: 500000.", "Amount: ."));
    REFUSE("a missing fraction digit (NODUS)", mutate(g, "500000.00000000 NODUS", "500000.0000000 NODUS"));
    REFUSE("an extra fraction digit (NODUS)", mutate(g, "500000.00000000 NODUS", "500000.000000000 NODUS"));
    REFUSE("a missing fraction digit (USDT)", mutate(g, "49.500000 USDT", "49.50000 USDT"));
    REFUSE("an extra fraction digit (USDT)", mutate(g, "49.500000 USDT", "49.5000000 USDT"));
    REFUSE("no fraction at all", mutate(g, "500000.00000000 NODUS", "500000 NODUS"));
    REFUSE("a comma for the point", mutate(g, "500000.00000000", "500000,00000000"));
    REFUSE("the wrong unit word (USDT for NODUS)", mutate(g, "00000000 NODUS", "00000000 USDT"));
    REFUSE("the wrong unit word (NODUS for USDT)", mutate(g, "49.500000 USDT", "49.500000 NODUS"));
    REFUSE("a lower-case unit word", mutate(g, "NODUS\nMinimum", "nodus\nMinimum"));
    REFUSE("no space before the unit", mutate(g, "00000000 NODUS", "00000000NODUS"));
    REFUSE("a sign on the amount", mutate(g, "Amount: 5", "Amount: +5"));
    REFUSE("the raw NODUS amount above 2^64 - 1", mutate(g, "500000.00000000 NODUS", "184467440737.09551616 NODUS"));
    REFUSE("the raw USDT amount above 2^64 - 1", mutate(g, "49.500000 USDT", "18446744073709.551616 USDT"));
    REFUSE("a NODUS integer part far above the bound", mutate(g, "500000.00000000 NODUS", "999999999999999999999.00000000 NODUS"));
    REFUSE("the request number 2^64", mutate(g, "9007199254740993", "18446744073709551616"));
    REFUSE("a leading zero in the request number", mutate(g, "9007199254740993", "09007199254740993"));
    REFUSE("a sign in the request number", mutate(g, "Request Number: 9", "Request Number: +9"));
    REFUSE("an empty request number", mutate(g, "Request Number: 9007199254740993", "Request Number: "));
    REFUSE("a CR at the end of a line", mutate(g, "NODUS\n", "NODUS\r\n"));
    REFUSE("a CR at the end of the text", mutate(g, "9007199254740993", "9007199254740993\r"));
    REFUSE("a tab", mutate(g, "Sender: ", "Sender:\t"));
    REFUSE("a tab inside a value", mutate(g, "500000.00000000 NODUS", "500000.00000000\tNODUS"));
    REFUSE("a trailing LF", mutate(g, "9007199254740993", "9007199254740993\n"));
    REFUSE("a trailing space", mutate(g, "9007199254740993", "9007199254740993 "));
    REFUSE("a space at the end of a line", mutate(g, "NODUS\nMinimum", "NODUS \nMinimum"));
    REFUSE("two spaces after a colon", mutate(g, "Amount: ", "Amount:  "));
    REFUSE("no space after a colon", mutate(g, "Amount: ", "Amount:"));
    REFUSE("a space before a colon", mutate(g, "Amount: ", "Amount : "));
    REFUSE("an empty line between lines", mutate(g, "\nAmount:", "\n\nAmount:"));
    REFUSE("an unknown key in place of Transfer ID", mutate(g, "\nTransfer ID: ", "\nXfer: "));
    {
        char line[160];
        snprintf(line, sizeof(line), "Transfer ID: %s\n", TID);
        REFUSE("a missing key (the Transfer ID line removed)", mutate(g, line, ""));
    }
    REFUSE("an unknown key", mutate(g, "Minimum To Receive:", "Minimum:"));
    REFUSE("a wrong key case", mutate(g, "Transfer ID:", "Transfer Id:"));
    REFUSE("a wrong title", mutate(g, "Nodus Swap: NODUS to USDT request", "Nodus Swap: NODUS to USDT quote"));
    REFUSE("a title in another case", mutate(g, "Nodus Swap:", "nodus swap:"));
    {
        char t127[129];
        memcpy(t127, TID, 127); t127[127] = '\0';
        REFUSE("a transfer id of 127 digits", mutate(g, TID, t127));
    }
    REFUSE("the last line missing", mutate(g, "\nRequest Number: 9007199254740993", ""));
    {   /* a key repeated: the Amount line twice instead of Minimum */
        txt_t t = mutate(g, "\nMinimum To Receive: 49.500000 USDT", "\nAmount: 500000.00000000 NODUS");
        REFUSE("a repeated key (Amount twice, Minimum missing)", t);
        /* reordered: swap Amount and Minimum To Receive lines */
        t = mutate(g, "Amount: 500000.00000000 NODUS\nMinimum To Receive: 49.500000 USDT",
                      "Minimum To Receive: 49.500000 USDT\nAmount: 500000.00000000 NODUS");
        REFUSE("keys reordered", t);
        /* an extra key line at the end */
        t = g;
        t.n += (size_t)snprintf(t.t + t.n, sizeof(t.t) - t.n, "\nNote: x");
        REFUSE("an extra line after the last key", t);
        /* a repeated last key */
        t = g;
        t.n += (size_t)snprintf(t.t + t.n, sizeof(t.t) - t.n, "\nRequest Number: 1");
        REFUSE("the last key repeated", t);
    }
    {   /* bytes that are not ASCII 0x20-0x7E / LF */
        txt_t t = mutate(g, "Nodus Swap:", "N\xc3\xb6" "dus Swap:");
        REFUSE("a non-ASCII byte", t);
        t = g; t.t[10] = '\x01';
        REFUSE("a control byte", t);
        t = g; t.t[10] = '\x7f';
        REFUSE("the DEL byte", t);
        t = g; t.t[10] = '\0';
        REFUSE("a NUL byte in the text", t);
    }
    {   /* above the longest canonical text, and empty */
        txt_t t = g;
        memset(t.t + t.n, 'a', 40);          /* 541 + 40 = 581 > 574 */
        t.n += 40; t.t[t.n] = '\0';
        REFUSE("a text of more than 574 bytes", t);
        txt_t big;
        memset(big.t, 'a', 700); big.t[700] = '\0'; big.n = 700;
        REFUSE("a 700-byte text", big);
    }
    {   /* an empty text */
        txt_t e;
        e.t[0] = '\0'; e.n = 0;
        amm_req_nodus_to_usdt_t o;
        sign_with(g_id1, GOOD_ORIGIN, &g);          /* any signature */
        amm_req_nodus_in_t in = nin(&e, g_id1);
        in.text = (const uint8_t *)g.t;             /* non-NULL pointer, length 0 */
        in.text_len = 0;
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_FORMAT,
              "an empty text refused as a format fault");
    }
    /* the same rules in the two liquidity kinds */
    {
        txt_t a = good_la();
        CHECK(a.n > 0, "control text built");
        amm_req_liq_eth_in_t e = la_eth(V_ADDR, g_addr1, "30000000", "3000000000000", "77");
        a = la_text(V_ADDR, g_addr1, "30.000000 USDT", "30000.00000000 NODUS", TID, g_chain_hex, "77");
        CHECK(la_rc(&e, &a) == AMM_REQ_OK, "control: liquidity add passes under the same helper");
        txt_t b = mutate(a, "USDT Amount: 30.000000 USDT", "USDT Amount: 30.00000 USDT");
        CHECK(la_rc(&e, &b) == AMM_REQ_FORMAT, "liquidity add: a missing fraction digit refused");
        b = mutate(a, "NODUS Amount: ", "NODUS  Amount: ");
        CHECK(la_rc(&e, &b) == AMM_REQ_FORMAT, "liquidity add: a wrong key refused");
        b = mutate(a, "Ethereum Address: ", "Nodus Address: ");
        CHECK(la_rc(&e, &b) == AMM_REQ_FORMAT, "liquidity add: a repeated key refused");
        b = mutate(a, "Transfer ID: ", "Transfer Id: ");
        CHECK(la_rc(&e, &b) == AMM_REQ_FORMAT, "liquidity add: a wrong key case refused");
        b = a; b.t[b.n++] = '\n'; b.t[b.n] = '\0';
        CHECK(la_rc(&e, &b) == AMM_REQ_FORMAT, "liquidity add: a trailing LF refused");
        b = mutate(a, "Request Number: 77", "Request Number: 077");
        CHECK(la_rc(&e, &b) == AMM_REQ_FORMAT, "liquidity add: a leading zero in the number refused");
        b = mutate(a, "liquidity add request", "liquidity withdraw request");
        CHECK(la_rc(&e, &b) == AMM_REQ_FORMAT, "liquidity add: the withdraw title refused");
    }
    {
        txt_t w = good_lw();
        CHECK(lw_rc(&w) == AMM_REQ_OK, "control: withdraw passes under the same helper");
        txt_t b = mutate(w, "Basis Points: 2500", "Basis Points: 0");
        CHECK(lw_rc(&b) == AMM_REQ_FORMAT, "withdraw: basis points 0 refused");
        b = mutate(w, "Basis Points: 2500", "Basis Points: 10001");
        CHECK(lw_rc(&b) == AMM_REQ_FORMAT, "withdraw: basis points 10001 refused");
        b = mutate(w, "Basis Points: 2500", "Basis Points: 02500");
        CHECK(lw_rc(&b) == AMM_REQ_FORMAT, "withdraw: a leading zero in basis points refused");
        b = mutate(w, "Basis Points: 2500", "Basis Points: -5");
        CHECK(lw_rc(&b) == AMM_REQ_FORMAT, "withdraw: negative basis points refused");
        b = mutate(w, "Basis Points: 2500", "Basis Points: 2500.0");
        CHECK(lw_rc(&b) == AMM_REQ_FORMAT, "withdraw: a fraction in basis points refused");
        b = mutate(w, "Basis Points: 2500\n", "");
        CHECK(lw_rc(&b) == AMM_REQ_FORMAT, "withdraw: a missing key refused");
        b = mutate(w, "Chain ID: ", "Chain ID:  ");
        CHECK(lw_rc(&b) == AMM_REQ_FORMAT, "withdraw: two spaces after a colon refused");
        b = mutate(w, "liquidity withdraw request", "NODUS to USDT request");
        CHECK(lw_rc(&b) == AMM_REQ_FORMAT, "withdraw: another kind's title refused");
    }
#undef REFUSE
}

static void n_checks(void) {
    printf("N chain id, address, signature\n");
    txt_t g = good_nu();

    /* a Chain ID other than the node's is its own refusal */
    {
        char other[65];
        memcpy(other, g_chain_hex, 65);
        other[0] = (other[0] == '0') ? '1' : '0';
        txt_t t = mutate(g, g_chain_hex, other);
        CHECK(nu_rc(&t) == AMM_REQ_CHAIN, "a Chain ID other than the node's refused");
        txt_t w = lw_text(V_ADDR, g_addr1, "100", other, "5");
        CHECK(lw_rc(&w) == AMM_REQ_CHAIN, "withdraw: a Chain ID other than the node's refused");
        txt_t a = la_text(V_ADDR, g_addr1, "30.000000 USDT", "3000.00000000 NODUS", TID, other, "77");
        amm_req_liq_eth_in_t e = la_eth(V_ADDR, g_addr1, "30000000", "300000000000", "77");
        CHECK(la_rc(&e, &a) == AMM_REQ_CHAIN, "liquidity add: a Chain ID other than the node's refused");
    }

    /* the Nodus address is not SHA3-512(public key) */
    {
        txt_t t = nu_text(g_addr2, ETHD, "500000.00000000 NODUS", "49.500000 USDT", TID,
                          g_chain_hex, "1");
        CHECK(nu_rc(&t) == AMM_REQ_ADDRESS,
              "Sender is another key's address (signed by key 1): refused");
        txt_t z = nu_text("0000000000000000000000000000000000000000000000000000000000000000"
                          "0000000000000000000000000000000000000000000000000000000000000000",
                          ETHD, "500000.00000000 NODUS", "49.500000 USDT", TID, g_chain_hex, "1");
        CHECK(nu_rc(&z) == AMM_REQ_ADDRESS, "Sender 128 zeros refused");
        txt_t w = lw_text(V_ADDR, g_addr2, "100", g_chain_hex, "5");
        CHECK(lw_rc(&w) == AMM_REQ_ADDRESS, "withdraw: Nodus Address is not the key's address: refused");
    }

    /* signature faults */
    {
        amm_req_nodus_to_usdt_t o;
        amm_req_nodus_in_t in;
        sign_with(g_id1, "https://evil.example", &g);
        in = nin(&g, g_id1);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_SIGNATURE,
              "signed over another origin: refused");
        sign_with(g_id1, GOOD_ORIGIN "/", &g);
        in = nin(&g, g_id1);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_SIGNATURE,
              "signed over the origin with a trailing slash: refused");
        sign_with(g_id1, "http://swap.nodusnetwork.io", &g);
        in = nin(&g, g_id1);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_SIGNATURE,
              "signed over http instead of https: refused");
        sign_with(g_id1, GOOD_ORIGIN, &g);
        in = nin(&g, g_id1);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_OK,
              "control: the same text signed over the good origin verifies");
        amm_cfg_t oc = g_cfg;
        strcpy(oc.expected_origin, "https://other.example");
        CHECK(amm_req_nodus_to_usdt_verify(&oc, g_j, &in, &o) == AMM_REQ_SIGNATURE,
              "the setting expected_origin is the one checked against");

        /* another key's public key with this text: its address is not Sender */
        in = nin(&g, g_id2);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_ADDRESS,
              "another public key than the one the text names: refused");
        /* the address matches key 2, the signature is key 1's */
        txt_t t2 = nu_text(g_addr2, ETHD, "500000.00000000 NODUS", "49.500000 USDT", TID,
                           g_chain_hex, "1");
        sign_with(g_id1, GOOD_ORIGIN, &t2);
        in = nin(&t2, g_id2);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_SIGNATURE,
              "the text names key 2, the signature is key 1's: refused");
        /* a flipped signature byte */
        sign_with(g_id1, GOOD_ORIGIN, &g);
        g_sig.bytes[100] ^= 0x01;
        in = nin(&g, g_id1);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_SIGNATURE,
              "a flipped signature byte: refused");
        /* the signed text changed after signing: one digit of the amount */
        sign_with(g_id1, GOOD_ORIGIN, &g);
        txt_t t3 = mutate(g, "500000.00000000", "500001.00000000");
        in = nin(&t3, g_id1);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_SIGNATURE,
              "the text changed after signing: refused");
        /* a NULL text is a fault, not a pass */
        in.text = NULL;
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, g_j, &in, &o) == AMM_REQ_ERR,
              "a NULL text is a fault");
    }
}

static void l_pair(void) {
    printf("L liquidity add: the two halves must agree\n");
    amm_req_liq_eth_in_t e = la_eth(V_ADDR, g_addr1, "30000000", "300000000000", "77");
    txt_t x = la_text(V_ADDR, g_addr1, "30.000000 USDT", "3000.00000000 NODUS", TID, g_chain_hex, "77");
    CHECK(la_rc(&e, &x) == AMM_REQ_OK, "control: the pair agrees");

    txt_t t = mutate(x, "30.000000 USDT", "30.000001 USDT");
    CHECK(la_rc(&e, &t) == AMM_REQ_PAIR, "USDT amount differs by one raw unit: refused");
    t = mutate(x, "3000.00000000 NODUS", "3000.00000001 NODUS");
    CHECK(la_rc(&e, &t) == AMM_REQ_PAIR, "NODUS amount differs by one raw unit: refused");
    t = mutate(x, "Request Number: 77", "Request Number: 78");
    CHECK(la_rc(&e, &t) == AMM_REQ_PAIR, "request number differs: refused");
    t = mutate(x, V_ADDR, "0x29e7e376e7c213b7e7e7e46cc70a5dd086daff2a");
    CHECK(la_rc(&e, &t) == AMM_REQ_PAIR, "Ethereum address differs: refused");
    amm_req_liq_eth_in_t e2 = la_eth(V_ADDR, g_addr2, "30000000", "300000000000", "77");
    CHECK(la_rc(&e2, &x) == AMM_REQ_PAIR, "Nodus address differs (typed half names key 2): refused");
    e2 = la_eth(V_ADDR, g_addr1, "30000001", "300000000000", "77");
    CHECK(la_rc(&e2, &x) == AMM_REQ_PAIR, "the typed half's USDT amount differs: refused");
    e2 = la_eth(V_ADDR, g_addr1, "30000000", "300000000001", "77");
    CHECK(la_rc(&e2, &x) == AMM_REQ_PAIR, "the typed half's NODUS amount differs: refused");
    e2 = la_eth(V_ADDR, g_addr1, "30000000", "300000000000", "76");
    CHECK(la_rc(&e2, &x) == AMM_REQ_PAIR, "the typed half's request number differs: refused");
    /* a bad half is its own refusal first */
    e2 = e; e2.signature[64] = 0;
    CHECK(la_rc(&e2, &x) == AMM_REQ_SIGNATURE, "the typed half with last byte 0: refused");
    e2 = e; e2.signature[5] ^= 1;
    CHECK(la_rc(&e2, &x) == AMM_REQ_SIGNATURE, "the typed half with a flipped byte: refused");
    e2 = e; e2.nodus_address = "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
                               "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB";
    CHECK(la_rc(&e2, &x) == AMM_REQ_FORMAT, "the typed half's Nodus address in capitals: refused");
    /* the ethers-signed typed half (Nodus address "ab" x 64) is bound to that address */
    amm_req_liq_eth_in_t ev;
    memset(&ev, 0, sizeof(ev));
    ev.ethereum_address = V_ADDR; ev.nodus_address = V_DEST; ev.usdt_amount = "30000000";
    ev.nodus_amount = "300000000000"; ev.request_number = "77";
    unhex(V_SIG_L_1, ev.signature, 65);
    CHECK(la_rc(&ev, &x) == AMM_REQ_PAIR,
          "the ethers-signed typed half verifies by itself and is then refused as a pair "
          "against a text with another Nodus address");
}

/* ── request numbers ──────────────────────────────────────────────────── */

static void mark(amm_journal_t *j, amm_dir_t dir, const char *sender, const char *dest,
                 const uint8_t req_no[32], const char *incoming, int salt) {
    amm_approve_t a;
    amm_swap_t s;
    memset(&a, 0, sizeof(a));
    a.dir = dir; a.sender = sender; a.dest = dest;
    a.amount = 50000000ULL; a.minimum = 1; a.value_usdt = 50000000ULL;
    a.approved_at = 1000; a.expiry = 1300; a.approved_tip = 100;
    a.incoming_id = incoming;
    memcpy(a.req_no, req_no, 32);
    for (int i = 0; i < 16; i++) a.rand16[i] = (uint8_t)(salt * 17 + i);
    a.swap_max = 100000000ULL; a.inflight_max = 500000000ULL;
    if (amm_journal_approve(j, &a, &s) != AMM_J_OK) {
        printf("FATAL: could not write a request-number marker\n");
        exit(2);
    }
}

static void r_reuse(void) {
    printf("R request numbers\n");
    /* USDT -> NODUS: Ethereum address, 40 hex, key of the journal's store */
    int n = g_jn;
    amm_journal_t *j = fresh_journal();
    amm_req_usdt_in_t in = vec_usdt();
    amm_req_usdt_t o;
    CHECK(amm_req_usdt_verify(&g_cfg, j, &in, &o) == AMM_REQ_OK, "fresh journal: the request is accepted");
    mark(j, AMM_USDT_TO_NODUS, o.sender, o.destination, o.req_no, "", 1);
    CHECK(amm_req_usdt_verify(&g_cfg, j, &in, &o) == AMM_REQ_REUSED, "after the approval: the number is refused");
    amm_journal_close(j);
    j = reopen_journal(n);
    CHECK(amm_req_usdt_verify(&g_cfg, j, &in, &o) == AMM_REQ_REUSED,
          "after closing and reopening the journal: still refused");
    amm_req_usdt_in_t other = usdt_in(V_ADDR, V_DEST, "50000000", "490000000000", "10", V_SIG_U_1_N10);
    CHECK(amm_req_usdt_verify(&g_cfg, j, &other, &o) == AMM_REQ_OK,
          "another request number from the same address is accepted");
    amm_journal_t *fresh = fresh_journal();
    CHECK(amm_req_usdt_verify(&g_cfg, fresh, &in, &o) == AMM_REQ_OK,
          "the same request in another journal is accepted (the store is the journal's)");
    amm_journal_close(fresh);
    /* the high-s twin carries the same number: refused as a reuse */
    {
        amm_req_usdt_in_t tw = vec_usdt();
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int d = (int)ORDER_N[i] - (int)in.signature[32 + i] - borrow;
            borrow = d < 0;
            tw.signature[32 + i] = (uint8_t)(d + (borrow ? 256 : 0));
        }
        tw.signature[64] = (uint8_t)(55 - in.signature[64]);
        CHECK(amm_req_usdt_verify(&g_cfg, j, &tw, &o) == AMM_REQ_REUSED,
              "a second valid signature over the same message is refused as a reuse");
    }
    amm_journal_close(j);

    /* NODUS -> USDT: the Nodus address */
    n = g_jn;
    j = fresh_journal();
    txt_t x = good_nu();
    amm_req_nodus_to_usdt_t no;
    sign_with(g_id1, GOOD_ORIGIN, &x);
    amm_req_nodus_in_t nin_ = nin(&x, g_id1);
    CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, j, &nin_, &no) == AMM_REQ_OK, "NODUS -> USDT: accepted when new");
    char inc[140];
    snprintf(inc, sizeof(inc), "nodus:%s", no.transfer_id);
    mark(j, AMM_NODUS_TO_USDT, no.sender, no.destination, no.req_no, inc, 2);
    CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, j, &nin_, &no) == AMM_REQ_REUSED,
          "NODUS -> USDT: the number is refused after the approval");
    amm_journal_close(j);
    j = reopen_journal(n);
    CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, j, &nin_, &no) == AMM_REQ_REUSED,
          "NODUS -> USDT: still refused after a restart");
    {
        txt_t y = nu_text(g_addr1, ETHD, "500000.00000000 NODUS", "49.500000 USDT", TID,
                          g_chain_hex, "9007199254740994");
        sign_with(g_id1, GOOD_ORIGIN, &y);
        amm_req_nodus_in_t in2 = nin(&y, g_id1);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, j, &in2, &no) == AMM_REQ_OK,
              "NODUS -> USDT: another number from the same address is accepted");
        /* the Nodus text's request number under an Ethereum address of the same
         * number is a different store key: key 2 with number ...993 is new */
    }
    {
        txt_t z = nu_text(g_addr2, ETHD, "500000.00000000 NODUS", "49.500000 USDT", TID,
                          g_chain_hex, "9007199254740993");
        sign_with(g_id2, GOOD_ORIGIN, &z);
        amm_req_nodus_in_t in3 = nin(&z, g_id2);
        CHECK(amm_req_nodus_to_usdt_verify(&g_cfg, j, &in3, &no) == AMM_REQ_OK,
              "NODUS -> USDT: the same number from another address is accepted");
    }
    amm_journal_close(j);

    /* withdraw: the Nodus address */
    n = g_jn;
    j = fresh_journal();
    txt_t w = good_lw();
    amm_req_liq_withdraw_t wo;
    sign_with(g_id1, GOOD_ORIGIN, &w);
    amm_req_nodus_in_t win = nin(&w, g_id1);
    CHECK(amm_req_liquidity_withdraw_verify(&g_cfg, j, &win, &wo) == AMM_REQ_OK, "withdraw: accepted when new");
    mark(j, AMM_NODUS_TO_USDT, wo.nodus_address, wo.ethereum_address, wo.req_no, "nodus:aa", 3);
    CHECK(amm_req_liquidity_withdraw_verify(&g_cfg, j, &win, &wo) == AMM_REQ_REUSED,
          "withdraw: refused when the Nodus address used the number");
    amm_journal_close(j);

    /* add: either address */
    amm_req_liq_eth_in_t e = la_eth(V_ADDR, g_addr1, "30000000", "300000000000", "77");
    txt_t a = la_text(V_ADDR, g_addr1, "30.000000 USDT", "3000.00000000 NODUS", TID, g_chain_hex, "77");
    sign_with(g_id1, GOOD_ORIGIN, &a);
    amm_req_nodus_in_t ain = nin(&a, g_id1);
    amm_req_liq_add_t ao;
    uint8_t rn[32];
    memset(rn, 0, 32); rn[31] = 77;
    j = fresh_journal();
    CHECK(amm_req_liquidity_add_verify(&g_cfg, j, &e, &ain, &ao) == AMM_REQ_OK, "add: accepted when new");
    mark(j, AMM_NODUS_TO_USDT, g_addr1, V_ADDR + 2, rn, "nodus:bb", 4);
    CHECK(amm_req_liquidity_add_verify(&g_cfg, j, &e, &ain, &ao) == AMM_REQ_REUSED,
          "add: refused when the Nodus address used the number");
    amm_journal_close(j);
    j = fresh_journal();
    mark(j, AMM_USDT_TO_NODUS, V_ADDR + 2, g_addr1, rn, "", 5);
    CHECK(amm_req_liquidity_add_verify(&g_cfg, j, &e, &ain, &ao) == AMM_REQ_REUSED,
          "add: refused when the Ethereum address used the number");
    amm_journal_close(j);
}

static void s_settings(void) {
    printf("S the settings of this package\n");
    /* a refused request leaves no output behind */
    amm_req_usdt_in_t w = vec_usdt();
    w.signature[64] = 0;
    amm_req_usdt_t o;
    memset(&o, 0xaa, sizeof(o));
    CHECK(amm_req_usdt_verify(&g_cfg, g_j, &w, &o) == AMM_REQ_SIGNATURE &&
          o.amount == 0 && o.sender[0] == '\0', "a refused request leaves a zeroed output");
    CHECK(amm_req_usdt_verify(NULL, g_j, &w, &o) == AMM_REQ_ERR &&
          amm_req_usdt_verify(&g_cfg, NULL, &w, &o) == AMM_REQ_ERR,
          "a NULL cfg or journal is a fault");
    /* a fault also leaves a zeroed output (Sol verify 8, claim 10) */
    {
        amm_req_nodus_to_usdt_t on;
        amm_req_liq_add_t oa;
        amm_req_liq_withdraw_t ow;
        memset(&o, 0xaa, sizeof(o));
        memset(&on, 0xaa, sizeof(on));
        memset(&oa, 0xaa, sizeof(oa));
        memset(&ow, 0xaa, sizeof(ow));
        amm_req_usdt_t zu;
        amm_req_nodus_to_usdt_t zn;
        amm_req_liq_add_t za;
        amm_req_liq_withdraw_t zw;
        memset(&zu, 0, sizeof(zu));
        memset(&zn, 0, sizeof(zn));
        memset(&za, 0, sizeof(za));
        memset(&zw, 0, sizeof(zw));
        CHECK(amm_req_usdt_verify(NULL, g_j, &w, &o) == AMM_REQ_ERR &&
              memcmp(&o, &zu, sizeof(o)) == 0 &&
              amm_req_nodus_to_usdt_verify(NULL, g_j, NULL, &on) == AMM_REQ_ERR &&
              memcmp(&on, &zn, sizeof(on)) == 0 &&
              amm_req_liquidity_add_verify(NULL, g_j, NULL, NULL, &oa) == AMM_REQ_ERR &&
              memcmp(&oa, &za, sizeof(oa)) == 0 &&
              amm_req_liquidity_withdraw_verify(NULL, g_j, NULL, &ow) == AMM_REQ_ERR &&
              memcmp(&ow, &zw, sizeof(ow)) == 0,
              "a NULL argument leaves the output of each verify function zeroed");
    }
    uint8_t d[32], a[20];
    CHECK(amm_req_eth_recover(NULL, w.signature, a) == -1 &&
          amm_req_eip712_digest(NULL, d, d) == -1, "NULL arguments to the building blocks are refused");
}

/* Q1  a refused request's number is client text: the log line carries it only
 * when it is all decimal digits (operator order 2026-11-12: no secret reaches
 * the log; a client can put anything, e.g. a provider URL, in requestNumber).
 * PROVES: a request whose number is "https://p.test/KEY" is refused (FORMAT)
 * and the log FILE holds the line "not a decimal number (18 bytes)" and neither
 * the text nor "KEY"; a decimal number that is refused for another reason
 * (a bad signature) is written as its digits.
 * HOW IT CAN FALSELY PASS: the "not written" check is vacuous if the logger
 * wrote nothing; the two positive checks on the same file rule that out. */
static void q1_log_client_text(void) {
    printf("Q1 a client's request number in the log\n");
    char dir[] = "/tmp/test_amm_req_log_XXXXXX";
    if (!mkdtemp(dir)) { printf("FATAL mkdtemp\n"); exit(2); }
    char path[128];
    snprintf(path, sizeof(path), "%s/nodus-amm.log", dir);
    CHECK(nodus_log_file_open(dir, 1 << 20, 1) == 0, "the log file opens");
    amm_req_usdt_in_t in = vec_usdt();
    in.request_number = "https://p.test/KEY";
    CHECK(usdt_rc(&in) == AMM_REQ_FORMAT, "a non-decimal number is refused (format)");
    in = vec_usdt();
    in.request_number = "12345";
    CHECK(usdt_rc(&in) == AMM_REQ_SIGNATURE,
          "a decimal number that is not the signed one is refused as a bad signature");
    nodus_log_file_close();
    char buf[16384];
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(buf, 1, sizeof(buf) - 1, f) : 0;
    if (f) fclose(f);
    buf[n] = '\0';
    CHECK(strstr(buf, "the number is not a decimal number, 18 bytes") != NULL,
          "the line says the number is not decimal and its length");
    CHECK(strstr(buf, "p.test") == NULL && strstr(buf, "KEY") == NULL,
          "the client's text is not in the log file");
    CHECK(strstr(buf, "usdt_to_nodus request 12345:") != NULL, "a decimal number is written as digits");
    unlink(path);
    rmdir(dir);
}

int main(void) {
    printf("test_amm_req\n");
    amm_cfg_defaults(&g_cfg);
    strcpy(g_cfg.eip712_name, "Nodus Swap");
    strcpy(g_cfg.expected_origin, GOOD_ORIGIN);
    for (int i = 0; i < 32; i++) g_cfg.chain_id[i] = (uint8_t)(i * 7 + 3);
    snprintf(g_chain_hex, sizeof(g_chain_hex), "%s", hexof(g_cfg.chain_id, 32));
    CHECK(g_cfg.eth_chain_id == 1, "default eth_chain_id is 1 (the domain chainId)");

    g_id1 = new_id();
    g_id2 = new_id();
    addr_of(g_id1, g_addr1);
    addr_of(g_id2, g_addr2);
    memcpy(TID, V_DEST, 129);                 /* a 128-digit wire id: any value */
    for (int i = 0; i < 128; i += 2) { TID[i] = '0'; TID[i + 1] = (char)"0123456789abcdef"[(i / 2) % 16]; }
    memcpy(ETHD, "0x", 2);
    memcpy(ETHD + 2, "7e5f4552091a69125d5dfcb7b8c2659029395bdf", 41);

    char tmpl[] = "/tmp/amm_req_testXXXXXX";
    if (!mkdtemp(tmpl)) { printf("FATAL: mkdtemp\n"); return 2; }
    snprintf(g_dir, sizeof(g_dir), "%s", tmpl);
    g_j = fresh_journal();

    k1_mail();
    k2_digests();
    t_typed();
    n_valid();
    n_strict();
    n_checks();
    l_pair();
    r_reuse();
    s_settings();
    q1_log_client_text();

    amm_journal_close(g_j);
    cleanup();
    free(g_id1);
    free(g_id2);
    printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
