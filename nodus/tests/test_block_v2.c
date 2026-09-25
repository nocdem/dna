/**
 * Nodus — Ledger V2 O13: BlockHeader v3 + BlockID v3 tests (INACTIVE codec).
 *
 * KATs pinned from the independent python3 oracle
 * shared/dnac/tests/block_v3_oracle.py, which reproduces all FIVE shipped
 * v2 pins as CONTROL LEGS before emitting a single v3 vector (it refuses
 * to emit otherwise) — so these numbers are independently derived, not
 * echoed back from the implementation under test.
 *
 * Covers: the 413-byte encoding (offset spot-checks + digest pin), BlockID,
 * the genesis BlockID + full-32-byte chain-id derivation, the manifest-
 * mutation variant, the O13 domain_updates_root binding (incl. the tagged
 * EMPTY root that distinguishes a zero-envelope block from a missing body),
 * retired-vs-unknown version rejection as two distinct classes, strict
 * decode negatives, a full field-mutation sweep, and a DETERMINISTIC
 * (seeded xorshift) fuzz pass over the decoder and the domains-root input
 * path — no RNG, byte-reproducible.
 *
 * @file test_block_v2.c
 */

#include "dnac/block_v2.h"
#include "dnac/ledger_roots_v2.h"
#include "dnac/domain_wire.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        return 1; \
    } \
} while (0)

static int g_checks = 0;
#define OK() do { g_checks++; } while (0)

static void fill(uint8_t *dst, size_t len, uint8_t seed) {
    for (size_t i = 0; i < len; i++) dst[i] = (uint8_t)(seed + i * 7u);
}

static int hex_eq(const uint8_t *h, size_t n, const char *hex, const char *what) {
    static const char *d = "0123456789abcdef";
    char got[257];
    for (size_t i = 0; i < n && i < 128; i++) {
        got[2 * i] = d[h[i] >> 4]; got[2 * i + 1] = d[h[i] & 0xf];
    }
    got[2 * (n < 128 ? n : 128)] = 0;
    if (strcmp(got, hex) != 0) {
        fprintf(stderr, "KAT mismatch (%s):\n  pinned: %s\n  got:    %s\n",
                what, hex, got);
        return 0;
    }
    return 1;
}

/* python3-oracle literals (block_v3_oracle.py, control legs green) */
static const char *KAT_ENC_SHA =
    "30dee8495558347b4b0ca920553e80a2643c101b3b4b53efe4300dd806f98c56"
    "f814d62e66c5eafcbc06e3bc9634d1f25dfd29472fe0ad243357c261598062d4";
static const char *KAT_BLOCK_ID =
    "1403cb75a0e1d58f54c0987e2ffe5400e42b0bc382c70ce4e82b09e6baa9a2d0"
    "a077b07ccba8ae5926ff5beb60efbc4d1041258131a841f07d6793ae7dbed17e";
static const char *KAT_GENESIS_ID =
    "e68a2623907a0929c3fd8bd246a262481802f4fa76f48e7f226a73101fb2feee"
    "c4ffc869ad98c91515b3af798414da27297dfb8161289502466a8099ed8ea683";
static const char *KAT_GENESIS_CHAIN =
    "e68a2623907a0929c3fd8bd246a262481802f4fa76f48e7f226a73101fb2feee";
static const char *KAT_GENESIS_ID_MUT =
    "29675a73b74d6f25b07238e669377b635d4f095224fcfc2d398bb1c24426693e"
    "ac37bc4b3c0975811f609a82beb75e13a08a9419b1c595f6336e7b1def6a2794";
/* O13: the tagged EMPTY domain_updates_root ("DNA.E.DUPD.v1"), and the
 * BlockID of an otherwise-identical header carrying it. A zero-envelope
 * block MUST be distinguishable from one that touched domains. */
static const char *KAT_EMPTY_DUPD_ROOT =
    "661f403d91d807631ab6bcc82d34116780623aa35479c753fc1d53a722fa58bc"
    "61939dc88f51e2824ac76c8da4d11edc5beb54a0e3e222e2606320baf68de841";
static const char *KAT_BLOCK_ID_EMPTY_DUPD =
    "f49eb47f15b113ea1034ce2fb39d1e5f1ec510712d969ef00f65cccc2410f9e2"
    "def4284ee4c514d78d66bf281629bcdab4571b2a05d04da33c5e2334e337d43f";

static void base_header(dna_block_header_v2_t *h) {
    memset(h, 0, sizeof(*h));
    h->header_version = DNA_BH2_VERSION;
    fill(h->chain_id, 32, 0xA0);
    h->block_height = 5;
    h->epoch = 2;
    fill(h->prev_block_id, 64, 0xC0);
    fill(h->global_state_root, 64, 0xD0);
    fill(h->tx_root, 64, 0xE0);
    fill(h->domain_updates_root, 64, 0x55);
    fill(h->validator_set_hash, 64, 0xF0);
    h->tx_count = 3;
    fill(h->proposer_id, 32, 0x11);
    h->timestamp = 0x0102030405060708ULL;
}

/* The encoding is pinned two ways: OFFSET SPOT-CHECKS (every field at its
 * documented offset, literal bytes) + a digest of the full 413 bytes
 * pinned from the python oracle. */
#include "crypto/hash/qgp_sha3.h"

int main(void) {
    dna_block_header_v2_t h;
    base_header(&h);
    uint8_t enc[DNA_BH2_ENC_SIZE];
    CHECK(dna_bh2_encode(&h, enc) == 0, "encode"); OK();

    /* Offset spot checks per the documented v3 table. */
    CHECK(DNA_BH2_ENC_SIZE == 413 && DNA_BH2_BOUND_SIZE == 405,
          "v3 sizes drifted"); OK();
    CHECK(enc[0] == 3, "version @0"); OK();
    CHECK(enc[1] == 0xA0 && enc[32] == (uint8_t)(0xA0 + 31 * 7),
          "chain_id @1"); OK();
    CHECK(enc[33] == 0 && enc[40] == 5, "height BE @33"); OK();
    CHECK(enc[41] == 0 && enc[48] == 2, "epoch BE @41"); OK();
    CHECK(enc[49] == 0xC0, "prev @49"); OK();
    CHECK(enc[113] == 0xD0, "gsr @113"); OK();
    CHECK(enc[177] == 0xE0, "tx_root @177"); OK();
    CHECK(enc[241] == 0x55, "domain_updates_root @241"); OK();
    CHECK(enc[305] == 0xF0, "vset @305"); OK();
    CHECK(enc[369] == 0 && enc[372] == 3, "tx_count BE @369"); OK();
    CHECK(enc[373] == 0x11, "proposer @373"); OK();
    CHECK(enc[405] == 0x01 && enc[412] == 0x08, "timestamp BE @405"); OK();

    /* Whole-encoding digest pinned from the oracle. */
    uint8_t dg[64];
    CHECK(qgp_sha3_512(enc, sizeof(enc), dg) == 0, "sha");
    CHECK(hex_eq(dg, 64, KAT_ENC_SHA, "encoding digest"), "enc KAT"); OK();

    /* Round trip. */
    dna_block_header_v2_t back;
    CHECK(dna_bh2_decode(enc, sizeof(enc), &back) == 0, "decode"); OK();
    CHECK(back.header_version == 3 && back.block_height == 5 &&
          back.epoch == 2 && back.tx_count == 3 &&
          back.timestamp == h.timestamp &&
          memcmp(back.chain_id, h.chain_id, 32) == 0 &&
          memcmp(back.domain_updates_root, h.domain_updates_root, 64) == 0 &&
          memcmp(back.validator_set_hash, h.validator_set_hash, 64) == 0,
          "round trip"); OK();

    /* BlockID KAT + binding sweep. */
    uint8_t id[64], id2[64];
    CHECK(dna_bh2_block_id(&h, id) == 0, "block id");
    CHECK(hex_eq(id, 64, KAT_BLOCK_ID, "block id"), "id KAT"); OK();
    {
        dna_block_header_v2_t m;
        /* every field except timestamp changes the id */
        base_header(&m); m.chain_id[0] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "chain_id unbound"); OK();
        base_header(&m); m.block_height ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "height unbound"); OK();
        base_header(&m); m.epoch ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "epoch unbound"); OK();
        base_header(&m); m.prev_block_id[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "prev unbound"); OK();
        base_header(&m); m.global_state_root[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "gsr unbound"); OK();
        base_header(&m); m.tx_root[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "tx_root unbound"); OK();
        /* O13: the domain-update commitment MUST be bound. This is the
         * defect v3 exists to close — under v2 the whole DomainUpdate set
         * could be substituted without moving the BlockID. */
        base_header(&m); m.domain_updates_root[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "domain_updates_root unbound"); OK();
        base_header(&m); m.domain_updates_root[63] ^= 0x80;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "domain_updates_root last byte unbound"); OK();
        base_header(&m); m.validator_set_hash[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "vset unbound"); OK();
        base_header(&m); m.tx_count ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "tx_count unbound"); OK();
        base_header(&m); m.proposer_id[5] ^= 1;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) != 0,
              "proposer unbound"); OK();
        /* timestamp is informational: mutation must NOT change the id */
        base_header(&m); m.timestamp ^= 0xFFFF;
        CHECK(dna_bh2_block_id(&m, id2) == 0 && memcmp(id, id2, 64) == 0,
              "timestamp leaked into BlockID"); OK();
        /* version gate on hashing: the RETIRED version must not be
         * hashable under the new layout, nor may any unknown version. */
        base_header(&m); m.header_version = DNA_BH2_VERSION_RETIRED;
        CHECK(dna_bh2_block_id(&m, id2) != 0, "retired v2 header hashed"); OK();
        base_header(&m); m.header_version = 1;
        CHECK(dna_bh2_block_id(&m, id2) != 0, "v1 header hashed"); OK();
        base_header(&m); m.header_version = 4;
        CHECK(dna_bh2_block_id(&m, id2) != 0, "v4 header hashed"); OK();
    }

    /* O13 — zero-envelope vs populated. The tagged empty domain-updates
     * root is a REAL value the codec must carry, and it must produce a
     * DIFFERENT BlockID from any populated update set. Both the root
     * itself and the resulting id are oracle-pinned; the root is ALSO
     * cross-checked against the production dna_v2_domain_updates_root(),
     * so the test cannot drift from the shipped derivation. */
    {
        uint8_t empty_root[64];
        CHECK(dna_v2_domain_updates_root(NULL, 0, empty_root) == 0,
              "empty dupd root"); OK();
        CHECK(hex_eq(empty_root, 64, KAT_EMPTY_DUPD_ROOT, "empty dupd root"),
              "empty dupd KAT"); OK();

        dna_block_header_v2_t z;
        base_header(&z);
        memcpy(z.domain_updates_root, empty_root, 64);
        uint8_t zid[64];
        CHECK(dna_bh2_block_id(&z, zid) == 0, "zero-envelope id");
        CHECK(hex_eq(zid, 64, KAT_BLOCK_ID_EMPTY_DUPD, "zero-envelope id"),
              "zero-envelope id KAT"); OK();
        CHECK(memcmp(zid, id, 64) != 0,
              "zero-envelope block collides with a touching block"); OK();

        /* An all-zero root is NOT the empty root — a caller that simply
         * zeroed the field must not be mistaken for a legitimate
         * zero-envelope block. */
        dna_block_header_v2_t zz;
        base_header(&zz);
        memset(zz.domain_updates_root, 0, 64);
        uint8_t zzid[64];
        CHECK(dna_bh2_block_id(&zz, zzid) == 0, "zeroed field id");
        CHECK(memcmp(zzid, zid, 64) != 0,
              "all-zero field aliases the tagged empty root"); OK();
    }

    /* Decode negatives: truncation at every boundary class, trailing,
     * retired and unknown versions. */
    {
        dna_block_header_v2_t t;
        /* Boundaries: empty, after version, each 64-byte field start, the
         * bound/timestamp seam, and one byte short of the full encoding. */
        const size_t cuts[9] = { 0, 1, 33, 113, 241, 305, 369, 405, 412 };
        for (int i = 0; i < 9; i++) {
            CHECK(dna_bh2_decode(enc, cuts[i], &t) != 0, "truncated ok'd"); OK();
        }
        uint8_t big[DNA_BH2_ENC_SIZE + 1];
        memcpy(big, enc, sizeof(enc)); big[DNA_BH2_ENC_SIZE] = 0;
        CHECK(dna_bh2_decode(big, sizeof(big), &t) != 0, "trailing ok'd"); OK();
        uint8_t bad[DNA_BH2_ENC_SIZE];
        /* RETIRED version — a distinct class from "unknown": these bytes
         * were once valid and must never be reinterpreted under v3. */
        memcpy(bad, enc, sizeof(bad)); bad[0] = DNA_BH2_VERSION_RETIRED;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &t) != 0, "retired v2 ok'd");
        OK();
        /* UNKNOWN versions, below and above the current one. */
        memcpy(bad, enc, sizeof(bad)); bad[0] = 0;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &t) != 0, "v0 ok'd"); OK();
        memcpy(bad, enc, sizeof(bad)); bad[0] = 1;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &t) != 0, "v1 ok'd"); OK();
        memcpy(bad, enc, sizeof(bad)); bad[0] = 4;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &t) != 0, "v4 ok'd"); OK();
        memcpy(bad, enc, sizeof(bad)); bad[0] = 0xFF;
        CHECK(dna_bh2_decode(bad, sizeof(bad), &t) != 0, "v255 ok'd"); OK();
        CHECK(dna_bh2_decode(NULL, sizeof(enc), &t) != 0, "null ok'd"); OK();

        /* A v2-LENGTH buffer (349 bytes) must reject on length alone,
         * before any version consideration — no auto-detection by size. */
        CHECK(dna_bh2_decode(enc, 349, &t) != 0, "v2-length buffer ok'd"); OK();
    }

    /* Genesis: explicit semantics, manifest binding, 32-byte chain id. */
    {
        dna_block_header_v2_t g;
        base_header(&g);
        memset(g.chain_id, 0, 32);
        g.block_height = 0;
        g.epoch = 0;
        memset(g.prev_block_id, 0, 64);
        g.tx_count = 1;
        uint8_t manifest[64];
        memcpy(manifest, "DNA-TEST-MANIFEST-v1", 20);
        fill(manifest + 20, 44, 0x33);

        uint8_t gid[64], cid[32];
        CHECK(dna_bh2_genesis_block_id(&g, manifest, sizeof(manifest), gid) == 0,
              "genesis id");
        CHECK(hex_eq(gid, 64, KAT_GENESIS_ID, "genesis id"), "gid KAT"); OK();
        CHECK(dna_bh2_derive_chain_id(gid, cid) == 0, "derive");
        CHECK(hex_eq(cid, 32, KAT_GENESIS_CHAIN, "chain id"), "cid KAT"); OK();
        /* FULL 32-byte prefix: bytes 16..31 equal the id (never zeroed). */
        CHECK(memcmp(cid + 16, gid + 16, 16) == 0, "tail not from id"); OK();
        uint8_t z16[16] = { 0 };
        CHECK(memcmp(cid + 16, z16, 16) != 0, "tail zeroed (legacy bug)"); OK();

        /* Any manifest byte change changes genesis id AND chain id. */
        uint8_t gid2[64], cid2[32];
        manifest[0] ^= 1;
        CHECK(dna_bh2_genesis_block_id(&g, manifest, sizeof(manifest), gid2) == 0,
              "genesis id mut");
        CHECK(hex_eq(gid2, 64, KAT_GENESIS_ID_MUT, "genesis id mut"),
              "gid mut KAT"); OK();
        CHECK(dna_bh2_derive_chain_id(gid2, cid2) == 0 &&
              memcmp(cid, cid2, 32) != 0, "chain id not manifest-bound"); OK();
        manifest[0] ^= 1;

        /* Explicit genesis semantics enforced. */
        dna_block_header_v2_t badg = g;
        badg.block_height = 1;
        CHECK(dna_bh2_genesis_block_id(&badg, manifest, sizeof(manifest),
                                       gid2) != 0, "height!=0 ok'd"); OK();
        badg = g; badg.chain_id[3] = 1;
        CHECK(dna_bh2_genesis_block_id(&badg, manifest, sizeof(manifest),
                                       gid2) != 0, "nonzero chain ok'd"); OK();
        CHECK(dna_bh2_genesis_block_id(&g, NULL, 0, gid2) != 0,
              "null manifest ok'd"); OK();
        CHECK(dna_bh2_genesis_block_id(&g, manifest, 0, gid2) != 0,
              "empty manifest ok'd"); OK();
        CHECK(dna_bh2_genesis_block_id(&g, manifest,
                                       (size_t)DNA_BH2_MANIFEST_MAX + 1,
                                       gid2) != 0, "oversize manifest ok'd");
        OK();

        /* Non-genesis wrong-chain rejection. */
        uint8_t expect_chain[32];
        fill(expect_chain, 32, 0xA0);
        CHECK(dna_bh2_check_chain(&h, expect_chain) == 0, "chain match"); OK();
        expect_chain[7] ^= 1;
        CHECK(dna_bh2_check_chain(&h, expect_chain) != 0,
              "wrong chain accepted"); OK();
    }

    /* ── Deterministic fuzz (seeded xorshift64 — reproducible, no RNG) ── */
    {
        uint64_t s = 0x53325F46555A5A31ULL;   /* fixed seed */
        #define XRND() (s ^= s << 13, s ^= s >> 7, s ^= s << 17, s)
        uint8_t buf[512];
        dna_block_header_v2_t t;
        int decoded = 0;
        for (int it = 0; it < 20000; it++) {
            size_t len = (size_t)(XRND() % (sizeof(buf) + 1));
            for (size_t i = 0; i < len; i++) buf[i] = (uint8_t)XRND();
            int rc = dna_bh2_decode(buf, len, &t);
            /* Structural invariant: success ⇒ exact size + the CURRENT
             * version (never the retired one, never an unknown one). */
            if (rc == 0) {
                decoded++;
                CHECK(len == (size_t)DNA_BH2_ENC_SIZE &&
                      buf[0] == DNA_BH2_VERSION,
                      "fuzz decode invariant");
            }
        }
        OK();
        /* The random loop above essentially never produces a decodable
         * frame (it must hit BOTH the exact 413-byte length AND a leading
         * version byte), so on its own the success branch is unreachable
         * and the invariant would be vacuous — it would never execute even
         * if it asserted something false. Drive it deliberately: feed the
         * VALID encoding so the branch is taken at least once, and require
         * that it was. */
        {
            int before = decoded;
            for (int it = 0; it < 3; it++) {
                if (dna_bh2_decode(enc, sizeof(enc), &t) == 0) {
                    decoded++;
                    CHECK(sizeof(enc) == (size_t)DNA_BH2_ENC_SIZE &&
                          enc[0] == DNA_BH2_VERSION,
                          "driven fuzz invariant");
                }
            }
            CHECK(decoded > before,
                  "fuzz success branch never executed (vacuous invariant)");
            OK();
        }
        /* Structured mutations of a valid frame: decode either rejects or
         * re-encodes byte-identically (canonicality). */
        for (int it = 0; it < 5000; it++) {
            uint8_t m[DNA_BH2_ENC_SIZE];
            memcpy(m, enc, sizeof(m));
            m[XRND() % sizeof(m)] ^= (uint8_t)(XRND() | 1);
            if (dna_bh2_decode(m, sizeof(m), &t) == 0) {
                uint8_t re[DNA_BH2_ENC_SIZE];
                CHECK(dna_bh2_encode(&t, re) == 0 &&
                      memcmp(re, m, sizeof(m)) == 0, "fuzz canonicality");
            }
        }
        OK();
        /* Domains-root input fuzz: random head lists — acceptance implies
         * the SYSTEM-first strictly-sorted invariant. */
        for (int it = 0; it < 5000; it++) {
            dna_v2_domain_head_t heads[5];
            memset(heads, 0, sizeof(heads));
            size_t n = 1 + (size_t)(XRND() % 5);
            for (size_t i = 0; i < n; i++) {
                heads[i].domain_id = (uint32_t)(XRND() % 6);
                heads[i].domain_state_root[0] = (uint8_t)XRND();
                heads[i].status = (uint8_t)(XRND() % 4);
            }
            uint8_t r[64];
            if (dna_v2_domains_root(heads, n, r) == 0) {
                CHECK(heads[0].domain_id == 0, "fuzz: SYSTEM-first violated");
                for (size_t i = 1; i < n; i++)
                    CHECK(heads[i - 1].domain_id < heads[i].domain_id,
                          "fuzz: sort invariant violated");
            }
        }
        OK();
        #undef XRND
    }

    printf("test_block_v2: %d checks OK\n", g_checks);
    return 0;
}
