/**
 * Nodus — cometbft @709fd12b C port, wave R1-A: proto3 codec tests
 * (INACTIVE layer).
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 * That shared/dnac/cmt_pb.c produces THE BYTES THAT GET HASHED AND SIGNED
 * in the ported consensus, and that its decoder refuses everything a
 * remote peer could send that does not describe a message this chain
 * writes. If this file failed, one of these would be false:
 *   · the K-1 rev 2 encoding rules hold, each pinned by a case that would
 *     break if the rule were dropped:
 *       (a) OMIT-ZERO — Consensus{0,0}, HashedParams{0,0}, an empty
 *           ValidatorSet and a zero ExecTxResult all encode to NOTHING;
 *       (b) ALWAYS-EMIT — a zero BlockID is `12 00` and NOT empty, a zero
 *           Header is nineteen bytes and not zero, an Absent CommitSig is
 *           FIFTEEN bytes because its timestamp is still written;
 *       (c) the zero time is seconds = -62135596800, eleven bytes, and an
 *           out-of-range time is refused on both encode and decode;
 *       (e) sign bytes are uvarint(len) ‖ message, and canonical
 *           height/round are LITTLE-endian sfixed64 that are themselves
 *           omit-zero — the golden CanonicalVote has no round tag;
 *       (f) BitArray elems are PACKED under one tag;
 *       (g) a negative int64 is the ten-byte form (Int64Value{-3},
 *           HashedParams MaxGas = -1);
 *       (h) a PublicKey is branch 9, tag 0x4a, exactly 2592 bytes;
 *   · every message round-trips: decode(encode(m)) re-encodes to the same
 *     bytes, so no field is silently lost or added;
 *   · the decoder REFUSES, without reading out of bounds: a truncated
 *     buffer, a length that runs past the end, a varint with no
 *     terminator, a wrong wire type, an unknown group marker, a list
 *     longer than the caller's capacity, a byte field longer than its
 *     destination, a BitArray whose elems do not match its bits, a
 *     PublicKey on branch 1 or 2 or with a length of 2591 or 2593, a
 *     Timestamp below or above the valid range or with nanos >= 1e9, a
 *     Proof with 101 aunts, an ExecTxResult carrying a stripped field, and
 *     an Evidence on the light-client branch;
 *   · an UNKNOWN field number is SKIPPED, not refused, wherever the
 *     generated decoder skips it — being stricter than the reference is
 *     as wrong as being looser;
 *   · nothing decoded points into the input buffer: the input is
 *     overwritten after the decode and the decoded values survive.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build. No compile flags, no environment variables, no network,
 * no files, no clock, no RNG. Safe under `ctest -j`. Every negative case
 * decodes from a buffer sized EXACTLY to its input, so that a one-byte
 * over-read is a detectable fault: most from a `static const` array,
 * which ASan surrounds with a redzone as a global, and FOUR from an
 * exact-size heap allocation — the over-length PublicKey sweep, the
 * 65-byte hash into a 64-byte Header field, the 101-aunt Proof, and the
 * truncation sweep. Without a sanitizer all of them still assert the
 * return code but none can observe an over-read.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing. No files, no directories, no processes, no global state. Every
 * heap buffer it allocates is freed on the success path; a CHECK failure
 * returns early and leaks, which is acceptable in a failing test process.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. The vectors are produced by shared/dnac/tests/cmt_pb_oracle.py, an
 *     INDEPENDENT python encoder written from the pinned .proto field
 *     numbers and the K-1 rev 2 rules — not from cmt_pb.c. That makes them
 *     a real second opinion on the ENCODING, but both sides implement the
 *     same READING of the reference: if that reading is wrong, both are
 *     wrong together. Only opening the generated .pb.go at the cited lines
 *     can settle that. The one exception is the REV 3.2 golden set
 *     (zero Timestamp, Absent CommitSig, zero BlockID, the CanonicalVote
 *     and its delimited form, Int64Value, StringValue, HashedParams),
 *     which the oracle recomputes and which was derived before this port
 *     existed.
 *  2. Vectors longer than 40 bytes are pinned as (length, SHA3-512 of the
 *     encoding) rather than as literal arrays. That constrains the bytes
 *     exactly as tightly, but a reader cannot eyeball them — to see one,
 *     run the oracle.
 *  3. NO GO IMPLEMENTATION IS RUN. There is no C-versus-Go byte
 *     comparison anywhere in wave R1-A, so "matches cometbft" is a claim
 *     resting on reading, not on execution.
 *  4. The over-read assertions are only as strong as the sanitizer the
 *     suite runs under. Under a plain build they degrade to return-code
 *     checks.
 *  5. Nothing here builds a real block, a real vote or a real signature.
 *     It proves the CODEC, not that the right message is signed at the
 *     right time — that is wave R1-B / R1-C.
 *
 * @file test_cmt_pb.c
 */

#include "dnac/cmt_pb.h"
#include "dnac/cmt_merkle.h"
#include "dnac/cmt_bits.h"
#include "dnac/cmt_time.h"

#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdint.h>
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

/* ══ vectors — GENERATED by shared/dnac/tests/cmt_pb_oracle.py ════════ */

#define V_TS_ZERO_LEN 11
static const uint8_t V_TS_ZERO[11] = {
    0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x01,
};
#define V_TS_A_LEN 11
static const uint8_t V_TS_A[11] = {
    0x08, 0x80, 0xe2, 0xcf, 0xaa, 0x06, 0x10, 0x95, 0x9a, 0xef, 0x3a,
};
#define V_INT64VALUE_5_LEN 2
static const uint8_t V_INT64VALUE_5[2] = {
    0x08, 0x05,
};
#define V_INT64VALUE_NEG_LEN 11
static const uint8_t V_INT64VALUE_NEG[11] = {
    0x08, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
};
#define V_STRINGVALUE_AB_LEN 4
static const uint8_t V_STRINGVALUE_AB[4] = {
    0x0a, 0x02, 0x61, 0x62,
};
#define V_BYTESVALUE_HASH_A_LEN 66
static const char V_BYTESVALUE_HASH_A_SHA3[] =
    "079b42917ef9ee9b99d186e2a500ca77cde6280ba98934449e8195c55bcdca32"
    "27d64ab769c12ef1284daa187de3e78489ec8e98f8c14410484e29674289ffeb";
#define V_CONSENSUS_11_0_LEN 2
static const uint8_t V_CONSENSUS_11_0[2] = {
    0x08, 0x0b,
};
#define V_CONSENSUS_11_7_LEN 4
static const uint8_t V_CONSENSUS_11_7[4] = {
    0x08, 0x0b, 0x10, 0x07,
};
#define V_PSH_A_LEN 68
static const char V_PSH_A_SHA3[] =
    "3e38b40ca2a9c7734e37201fb4344be614a67b76c25431325c31cea9e1ac7d17"
    "4d7b0c52d6069d53eb37a20015e846dd00a9bc76a9bec1423a8142433d80d697";
#define V_BLOCKID_ZERO_LEN 2
static const uint8_t V_BLOCKID_ZERO[2] = {
    0x12, 0x00,
};
#define V_BLOCKID_A_LEN 136
static const char V_BLOCKID_A_SHA3[] =
    "8073f88776426a3c9ace6b8a1281f8c34f7ec89e0c7965eabab56ee59f7a6e66"
    "f7247059780bec4fe607bb7afc2e7f6a20eec9e24b346b02ae5657ecb441c65b";
#define V_PROOF_3AUNTS_LEN 268
static const char V_PROOF_3AUNTS_SHA3[] =
    "af2d5afd2f9d59cd9b5661be0ab7ebfd827ef0b8b2923cd12e46ec69c0b297de"
    "b5465a3e81819b6befd9affb0d6d197e53a8cafa1983ca44fc268928a3c7f619";
/* an empty aunt is one element: 22 00, not an omission */
#define V_PROOF_EMPTY_AUNT_LEN 13
static const uint8_t V_PROOF_EMPTY_AUNT[13] = {
    0x08, 0x02, 0x1a, 0x02, 0xb0, 0xb7, 0x22, 0x00, 0x22, 0x03, 0xb1, 0xb8,
    0xbf,
};
#define V_PART_ZERO_LEN 2
static const uint8_t V_PART_ZERO[2] = {
    0x1a, 0x00,
};
#define V_PART_A_LEN 148
static const char V_PART_A_SHA3[] =
    "76f41e2a8786bf6bd821c6e495b94113f6c5b999ac746dd4439b73dd237eb7bd"
    "5827616ce0346383a82e2c02426d2a0d34fcdde1baf6ac7900e273d34293cf47";
#define V_PUBKEY_FULL_2592_LEN 2595
static const char V_PUBKEY_FULL_2592_SHA3[] =
    "94ffefbaf5e49926ea69ee2d741cbaaba70c447cc271be02e32b9c73cab2d631"
    "9e49e2a10a6c2443f78aff33f993bbf6f864e1ceb7f2d451f5a8af7791f46d57";
#define V_PUBKEY_BAD_LEN_LEN 13
static const uint8_t V_PUBKEY_BAD_LEN[13] = {
    0x4a, 0x0b, 0x70, 0x77, 0x7e, 0x85, 0x8c, 0x93, 0x9a, 0xa1, 0xa8, 0xaf,
    0xb6,
};
#define V_PUBKEY_BRANCH1_LEN 34
static const uint8_t V_PUBKEY_BRANCH1[34] = {
    0x0a, 0x20, 0x11, 0x18, 0x1f, 0x26, 0x2d, 0x34, 0x3b, 0x42, 0x49, 0x50,
    0x57, 0x5e, 0x65, 0x6c, 0x73, 0x7a, 0x81, 0x88, 0x8f, 0x96, 0x9d, 0xa4,
    0xab, 0xb2, 0xb9, 0xc0, 0xc7, 0xce, 0xd5, 0xdc, 0xe3, 0xea,
};
#define V_PUBKEY_BRANCH2_LEN 35
static const uint8_t V_PUBKEY_BRANCH2[35] = {
    0x12, 0x21, 0x12, 0x19, 0x20, 0x27, 0x2e, 0x35, 0x3c, 0x43, 0x4a, 0x51,
    0x58, 0x5f, 0x66, 0x6d, 0x74, 0x7b, 0x82, 0x89, 0x90, 0x97, 0x9e, 0xa5,
    0xac, 0xb3, 0xba, 0xc1, 0xc8, 0xcf, 0xd6, 0xdd, 0xe4, 0xeb, 0xf2,
};
#define V_SIMPLEVAL_FULL_LEN 2600
static const char V_SIMPLEVAL_FULL_SHA3[] =
    "d4337f1581ea3a331d1b60c016c8df6f291895245504c1be171ac03ee75aafcc"
    "afccac640cb365f30063c469480f20751f9e5afb3a503872c9e43216e79d903c";
#define V_VALIDATOR_ZERO_LEN 2
static const uint8_t V_VALIDATOR_ZERO[2] = {
    0x12, 0x00,
};
#define V_VALIDATOR_FULL_LEN 2645
static const char V_VALIDATOR_FULL_SHA3[] =
    "2add13dc5b4ab0e6e1575d9af96e894ed231bd89e0265e223e09ff2808a04d22"
    "bd9542c4ab9776eb84130d970af99feab1d04f8759fb0e52d5000ddfcc799d1a";
#define V_VALSET_2_LEN 7938
static const char V_VALSET_2_SHA3[] =
    "4ccbbff57b6cd380a9966daecdd8f8935ab39c29e81cf3946a314dcfae3ebab5"
    "09c4a58646f62d0ce78e537c5773a0863e04d6b545b416b8c500d9f7e1bdb963";
#define V_HASHEDPARAMS_DEFAULT_LEN 16
static const uint8_t V_HASHEDPARAMS_DEFAULT[16] = {
    0x08, 0x80, 0x80, 0xc0, 0x0a, 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x01,
};
#define V_HEADER_ZERO_LEN 19
static const uint8_t V_HEADER_ZERO[19] = {
    0x0a, 0x00, 0x22, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff,
    0xff, 0xff, 0x01, 0x2a, 0x02, 0x12, 0x00,
};
#define V_HEADER_FULL_LEN 756
static const char V_HEADER_FULL_SHA3[] =
    "cc03edcb855013b8bf55cc1254acfdadc51e962c0ba41d733c64d7606f6a1f1f"
    "cc005021c04f239e105977e1d268ceabc0c7595e4d585b23b9eecb804e4d4759";
#define V_DATA_3TX_LEN 14
static const uint8_t V_DATA_3TX[14] = {
    0x0a, 0x03, 0x90, 0x97, 0x9e, 0x0a, 0x00, 0x0a, 0x05, 0x91, 0x98, 0x9f,
    0xa6, 0xad,
};
/* txs = {"", "ab", ""} — three elements, two of them empty */
#define V_DATA_EMPTY_ENDS_LEN 8
static const uint8_t V_DATA_EMPTY_ENDS[8] = {
    0x0a, 0x00, 0x0a, 0x02, 0x61, 0x62, 0x0a, 0x00,
};
#define V_VOTE_ZERO_LEN 17
static const uint8_t V_VOTE_ZERO[17] = {
    0x22, 0x02, 0x12, 0x00, 0x2a, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98,
    0xfe, 0xff, 0xff, 0xff, 0x01,
};
#define V_VOTE_SHORT_LEN 219
static const char V_VOTE_SHORT_SHA3[] =
    "266dcb9ee4741a3dc3ffe6a9e47c389bb8a23bc8b0583be959ce8a991f37c1bf"
    "9efc4460d42a742dbd955db7cf6dbd6fdf0099b4fabef49f0ee8edef5492e8c2";
#define V_VOTE_FULLSIG_LEN 9460
static const char V_VOTE_FULLSIG_SHA3[] =
    "c01f4b09726e604818c979f27d0b541706469c4a29224a5325255152c073bf78"
    "396dadd15fb353e7a138eb56985d4d05a343ffef661c317b5fc5affbf2815da7";
#define V_COMMITSIG_ABSENT_LEN 15
static const uint8_t V_COMMITSIG_ABSENT[15] = {
    0x08, 0x01, 0x1a, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff,
    0xff, 0xff, 0x01,
};
#define V_COMMITSIG_COMMIT_LEN 60
static const char V_COMMITSIG_COMMIT_SHA3[] =
    "217a18eb47aa39aaddd8fd42850f5352f8b50480b99085ff391efea27d441265"
    "d2ed5465ef38938887b4a3c2dcb55f08d08ace42e84a5b2e93bb68ec9802c18e";
#define V_COMMIT_ZERO_LEN 4
static const uint8_t V_COMMIT_ZERO[4] = {
    0x1a, 0x02, 0x12, 0x00,
};
#define V_COMMIT_3SIGS_LEN 284
static const char V_COMMIT_3SIGS_SHA3[] =
    "c50eb32bf811d884b0cdda697e5f485b04f6b5059a864e3709dec83abd817a8d"
    "e812e1614c2c65617d93d49d0605b77e180eedc149182905210e5d58b605aa05";
#define V_PROPOSAL_ZERO_LEN 17
static const uint8_t V_PROPOSAL_ZERO[17] = {
    0x2a, 0x02, 0x12, 0x00, 0x32, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98,
    0xfe, 0xff, 0xff, 0xff, 0x01,
};
#define V_PROPOSAL_A_LEN 180
static const char V_PROPOSAL_A_SHA3[] =
    "9b7339301b9ed78e84dacff1d005f6f5460259e2921d3564d2eed853f75199dc"
    "1b6d98b81d474f537e4e795bd4f13f63abffe088fc7ccb9942cb6c11f8a356ae";
#define V_CANONVOTE_GOLDEN_LEN 28
static const uint8_t V_CANONVOTE_GOLDEN[28] = {
    0x08, 0x02, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a,
    0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x01,
    0x32, 0x02, 0x61, 0x62,
};
#define V_CANONVOTE_GOLDEN_DELIM_LEN 29
static const uint8_t V_CANONVOTE_GOLDEN_DELIM[29] = {
    0x1c, 0x08, 0x02, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x2a, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff,
    0x01, 0x32, 0x02, 0x61, 0x62,
};
#define V_CANONVOTE_FULL_LEN 206
static const char V_CANONVOTE_FULL_SHA3[] =
    "68d3fd9bdfef2d5ac78028d57656c743f03c03459303206635a6d140c60b3462"
    "6d82aa89a54653ca555d1858a1a76a62bf0752105bd993d44fc7457e562bed20";
#define V_CANONPROPOSAL_A_LEN 217
static const char V_CANONPROPOSAL_A_SHA3[] =
    "6602b861ec1226327f5eb67077c0743eb3c0facc0bbfada4f713a4e69ff1ba72"
    "11008ab729b182d631ec6a547faf6eeae873ec1f67b8b65d6d14ef3691181aff";
#define V_CANONPROPOSAL_NILBID_LEN 28
static const uint8_t V_CANONPROPOSAL_NILBID[28] = {
    0x08, 0x20, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32,
    0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x01,
    0x3a, 0x02, 0x61, 0x62,
};
#define V_CANONVOTEEXT_A_LEN 60
static const char V_CANONVOTEEXT_A_SHA3[] =
    "7978de95163946b1f11a859fbdf4458b18d72e929a439ca4cb306c4fee620d84"
    "010bbc5fe4f80c913c5f87c1d43b05dc95a182c5c44e42a683bbeba0e7b49823";
#define V_DVE_A_LEN 434
static const char V_DVE_A_SHA3[] =
    "7e3eb0936e4ba288f4de0f5a96a35c80679a3758698d94510d368a30ff4c6a73"
    "3da5eb4de0c497356390586de072fb5c304adcee708318beb5403ca57e0669d8";
#define V_DVE_ZERO_LEN 13
static const uint8_t V_DVE_ZERO[13] = {
    0x2a, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff,
    0x01,
};
#define V_EVIDENCE_DVE_A_LEN 437
static const char V_EVIDENCE_DVE_A_SHA3[] =
    "cf87da48d8b6e3c854ca2fe1e53f7d67cbd0be984b378c279b3939399f7cbeea"
    "dc18c8bbb5699fff4159a3715d3c2f11b30d386fb657d6af4d5d9ab3cbe3a5fd";
#define V_EXECTXRESULT_A_LEN 15
static const uint8_t V_EXECTXRESULT_A[15] = {
    0x08, 0x07, 0x12, 0x05, 0xc0, 0xc7, 0xce, 0xd5, 0xdc, 0x28, 0xe8, 0x07,
    0x30, 0xe7, 0x07,
};
#define V_BITARRAY_3ELEMS_LEN 18
static const uint8_t V_BITARRAY_3ELEMS[18] = {
    0x08, 0x8c, 0x01, 0x12, 0x0d, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x01, 0xff, 0x1f,
};
#define V_BITARRAY_1BIT_LEN 5
static const uint8_t V_BITARRAY_1BIT[5] = {
    0x08, 0x01, 0x12, 0x01, 0x01,
};

/* ══ fixtures — the same inputs the oracle used ═══════════════════════ */

/* pat(n, seed): byte i = (seed + 7*i) mod 256 */
static void pat(uint8_t *out, size_t n, unsigned seed)
{
    size_t i;

    for (i = 0; i < n; i++) {
        out[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static uint8_t HASH_A[64], HASH_B[64], HASH_C[64];
static uint8_t ADDR_A[32], ADDR_B[32], CHAIN[32];
static uint8_t SIG_S[9];
static uint8_t KEY_FULL[2592];
static uint8_t SIG_FULL[4627];

static const cmt_time_t TS_A = { 1700000000LL, 123456789 };

static void build_fixtures(void)
{
    pat(HASH_A, sizeof(HASH_A), 0x10);
    pat(HASH_B, sizeof(HASH_B), 0x20);
    pat(HASH_C, sizeof(HASH_C), 0x30);
    pat(ADDR_A, sizeof(ADDR_A), 0x40);
    pat(ADDR_B, sizeof(ADDR_B), 0x41);
    pat(CHAIN,  sizeof(CHAIN),  0x50);
    pat(SIG_S,  sizeof(SIG_S),  0x60);
    pat(KEY_FULL, sizeof(KEY_FULL), 0x02);
    pat(SIG_FULL, sizeof(SIG_FULL), 0x01);
}

/* ══ comparison helpers ══════════════════════════════════════════════ */

static uint8_t g_buf[16384];
static uint8_t g_buf2[16384];
static uint8_t g_arena_bytes[16384];
static cmt_pb_arena_t g_arena;

static void arena_reset(void)
{
    g_arena.buf  = g_arena_bytes;
    g_arena.cap  = sizeof(g_arena_bytes);
    g_arena.used = 0;
}

static void to_hex(const uint8_t *b, size_t n, char *out)
{
    static const char *d = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i]     = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 0xf];
    }
    out[2 * n] = 0;
}

/* Compare an encoding against a literal vector. */
static int is_vec(const char *what, const uint8_t *got, size_t got_len,
                  const uint8_t *want, size_t want_len)
{
    if (got_len != want_len) {
        fprintf(stderr, "%s: length %zu, want %zu\n", what, got_len,
                want_len);
        return 0;
    }
    if (want_len != 0 && memcmp(got, want, want_len) != 0) {
        char a[3 * 64 + 1];
        size_t n = got_len < 32 ? got_len : 32;

        to_hex(got, n, a);
        fprintf(stderr, "%s: bytes differ (first %zu: %s)\n", what, n, a);
        return 0;
    }
    return 1;
}

/* Compare an encoding against (length, SHA3-512 of the encoding). */
static int is_digest(const char *what, const uint8_t *got, size_t got_len,
                     size_t want_len, const char *want_sha3)
{
    uint8_t h[64];
    char    hex[129];

    if (got_len != want_len) {
        fprintf(stderr, "%s: length %zu, want %zu\n", what, got_len,
                want_len);
        return 0;
    }
    if (qgp_sha3_512(got, got_len, h) != 0) {
        fprintf(stderr, "%s: hash backend failed\n", what);
        return 0;
    }
    to_hex(h, sizeof(h), hex);
    if (strcmp(hex, want_sha3) != 0) {
        fprintf(stderr, "%s: digest mismatch\n  got  %s\n  want %s\n",
                what, hex, want_sha3);
        return 0;
    }
    return 1;
}

/* ══ primitives ══════════════════════════════════════════════════════ */

static int test_primitives(void)
{
    size_t   off;
    uint64_t v;
    uint8_t  buf[16];

    /* sovTypes: how many bytes a uvarint occupies. */
    CHECK(cmt_pb_uvarint_size(0) == 1, "0");
    CHECK(cmt_pb_uvarint_size(1) == 1, "1");
    CHECK(cmt_pb_uvarint_size(127) == 1, "127");
    CHECK(cmt_pb_uvarint_size(128) == 2, "128");
    CHECK(cmt_pb_uvarint_size(16383) == 2, "16383");
    CHECK(cmt_pb_uvarint_size(16384) == 3, "16384");
    CHECK(cmt_pb_uvarint_size(UINT64_MAX) == 10, "uint64 max is 10 bytes");
    OK();

    /* A negative int64 widened to uint64 is the ten-byte form — rule (g),
     * and the reason Int64Value{-3} and HashedParams{MaxGas=-1} look the
     * way they do. */
    off = 0;
    CHECK(cmt_pb_put_uvarint(buf, sizeof(buf), &off,
                             (uint64_t)(int64_t)-1) == CMT_OK, "put -1");
    CHECK(off == 10, "-1 is ten bytes");
    off = 0;
    CHECK(cmt_pb_get_uvarint(buf, 10, &off, &v) == CMT_OK, "get -1");
    CHECK((int64_t)v == -1, "round trip -1");
    CHECK(off == 10, "consumed all ten");
    OK();

    /* The zero time's seconds, the vector every message with a timestamp
     * is built on. */
    off = 0;
    CHECK(cmt_pb_put_uvarint(buf, sizeof(buf), &off,
                             (uint64_t)CMT_TIME_MIN_SECONDS) == CMT_OK,
          "put min seconds");
    CHECK(is_vec("varint(zero-time seconds)", buf, off, V_TS_ZERO + 1,
                 V_TS_ZERO_LEN - 1), "the golden ten-byte varint");
    OK();

    /* Decode guards: a varint that never terminates, and one that runs
     * past the end of the buffer. Neither may read past `len`. */
    {
        static const uint8_t never_ends[11] = {
            0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80
        };
        static const uint8_t truncated[2] = { 0x80, 0x80 };

        off = 0;
        CHECK(cmt_pb_get_uvarint(never_ends, sizeof(never_ends), &off, &v)
              == CMT_REJECT, "a varint past 64 bits must REJECT");
        off = 0;
        CHECK(cmt_pb_get_uvarint(truncated, sizeof(truncated), &off, &v)
              == CMT_REJECT, "an unterminated varint must REJECT");
        off = 0;
        CHECK(cmt_pb_get_uvarint(buf, 0, &off, &v) == CMT_REJECT,
              "an empty buffer must REJECT");
        OK();
    }

    /* An output buffer that cannot hold the varint REJECTs. */
    off = 0;
    CHECK(cmt_pb_put_uvarint(buf, 1, &off, 128) == CMT_REJECT, "no room");
    CHECK(off == 0, "a refused put must not move the cursor");
    OK();

    /* MarshalDelimited — the outer frame of every sign-bytes preimage. */
    {
        size_t n = 0;

        CHECK(cmt_pb_marshal_delimited(V_CANONVOTE_GOLDEN,
                                       V_CANONVOTE_GOLDEN_LEN,
                                       g_buf, sizeof(g_buf), &n) == CMT_OK,
              "delimited");
        CHECK(is_vec("MarshalDelimited(CanonicalVote)", g_buf, n,
                     V_CANONVOTE_GOLDEN_DELIM,
                     V_CANONVOTE_GOLDEN_DELIM_LEN),
              "the golden delimited form");
        CHECK(cmt_pb_marshal_delimited(V_CANONVOTE_GOLDEN,
                                       V_CANONVOTE_GOLDEN_LEN, g_buf, 5, &n)
              == CMT_REJECT, "a short output buffer must REJECT");
        /* An empty message is still framed, as a single zero length. */
        CHECK(cmt_pb_marshal_delimited(NULL, 0, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "empty delimited");
        CHECK(n == 1 && g_buf[0] == 0x00, "an empty message frames to 00");
        OK();
    }
    return 0;
}

/* ══ Timestamp ═══════════════════════════════════════════════════════ */

static int test_timestamp(void)
{
    cmt_time_t t;
    size_t     n;

    cmt_pb_timestamp_init(&t);
    CHECK(t.seconds == CMT_TIME_MIN_SECONDS && t.nanos == 0,
          "init must give Go's zero time, not the epoch");
    CHECK(cmt_pb_timestamp_marshal(&t, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "marshal zero");
    CHECK(is_vec("Timestamp{zero}", g_buf, n, V_TS_ZERO, V_TS_ZERO_LEN),
          "the zero time is ELEVEN bytes");
    OK();

    /* The Unix epoch, on the other hand, is omit-zero on both fields and
     * encodes to NOTHING. This is the pair the CMT_TIME_ZERO warning is
     * about. */
    t.seconds = 0;
    t.nanos   = 0;
    CHECK(cmt_pb_timestamp_marshal(&t, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "marshal epoch");
    CHECK(n == 0, "the Unix epoch encodes to zero bytes");
    OK();

    t = TS_A;
    CHECK(cmt_pb_timestamp_marshal(&t, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "marshal TS_A");
    CHECK(is_vec("Timestamp{TS_A}", g_buf, n, V_TS_A, V_TS_A_LEN),
          "seconds then nanos, ascending field order");
    OK();

    /* Round trip, including the zero time. */
    CHECK(cmt_pb_timestamp_unmarshal(V_TS_A, V_TS_A_LEN, &t) == CMT_OK,
          "unmarshal TS_A");
    CHECK(t.seconds == TS_A.seconds && t.nanos == TS_A.nanos, "TS_A back");
    CHECK(cmt_pb_timestamp_unmarshal(V_TS_ZERO, V_TS_ZERO_LEN, &t) == CMT_OK,
          "unmarshal zero");
    CHECK(t.seconds == CMT_TIME_MIN_SECONDS && t.nanos == 0, "zero back");
    /* An EMPTY Timestamp message decodes to the proto zero {0,0} — the
     * Unix epoch — because that is what TimestampFromProto builds from an
     * all-default Timestamp. */
    CHECK(cmt_pb_timestamp_unmarshal(g_buf, 0, &t) == CMT_OK, "empty");
    CHECK(t.seconds == 0 && t.nanos == 0, "an empty Timestamp is 1970");
    OK();

    /* The range, refused on BOTH sides (rule c). */
    t.seconds = CMT_TIME_MIN_SECONDS - 1;
    t.nanos   = 0;
    CHECK(cmt_pb_timestamp_marshal(&t, g_buf, sizeof(g_buf), &n)
          == CMT_REJECT, "marshal below the range");
    t.seconds = CMT_TIME_MAX_SECONDS;
    CHECK(cmt_pb_timestamp_marshal(&t, g_buf, sizeof(g_buf), &n)
          == CMT_REJECT, "marshal at the exclusive maximum");
    t.seconds = 0;
    t.nanos   = 1000000000;
    CHECK(cmt_pb_timestamp_marshal(&t, g_buf, sizeof(g_buf), &n)
          == CMT_REJECT, "marshal nanos >= 1e9");
    t.nanos = -1;
    CHECK(cmt_pb_timestamp_marshal(&t, g_buf, sizeof(g_buf), &n)
          == CMT_REJECT, "marshal negative nanos");
    OK();

    {
        /* seconds = -62135596801, one below the minimum. */
        static const uint8_t below[11] = {
            0x08, 0xff, 0x91, 0xb8, 0xc3, 0x98, 0xfe, 0xff, 0xff, 0xff, 0x01
        };
        /* seconds = 253402300800, the exclusive upper bound. */
        static const uint8_t above[7] = {
            0x08, 0x80, 0x83, 0xd1, 0xff, 0xaf, 0x07
        };
        /* nanos = 1000000000 (field 2, five-byte varint). */
        static const uint8_t bad_nanos[6] = {
            0x10, 0x80, 0x94, 0xeb, 0xdc, 0x03
        };
        cmt_time_t got;

        CHECK(cmt_pb_timestamp_unmarshal(below, sizeof(below), &got)
              == CMT_REJECT, "decode below the range must REJECT");
        CHECK(cmt_pb_timestamp_unmarshal(above, sizeof(above), &got)
              == CMT_REJECT, "decode at the exclusive maximum must REJECT");
        CHECK(cmt_pb_timestamp_unmarshal(bad_nanos, sizeof(bad_nanos), &got)
              == CMT_REJECT, "decode nanos >= 1e9 must REJECT");
        /* One second below the maximum is the last VALID instant. */
        {
            uint8_t  ok_buf[16];
            size_t   off = 0;

            ok_buf[off++] = 0x08;
            CHECK(cmt_pb_put_uvarint(ok_buf, sizeof(ok_buf), &off,
                                     (uint64_t)(CMT_TIME_MAX_SECONDS - 1))
                  == CMT_OK, "put");
            CHECK(cmt_pb_timestamp_unmarshal(ok_buf, off, &got) == CMT_OK,
                  "one second below the maximum must be ACCEPTED");
            CHECK(got.seconds == CMT_TIME_MAX_SECONDS - 1, "value back");
        }
        OK();
    }
    return 0;
}

/* ══ header leaves (cdcEncode) ═══════════════════════════════════════ */

static int test_cdc_encode(void)
{
    size_t n;
    bool   is_nil;

    CHECK(cmt_pb_cdc_encode_int64(5, g_buf, sizeof(g_buf), &n, &is_nil)
          == CMT_OK, "Int64Value{5}");
    CHECK(is_vec("Int64Value{5}", g_buf, n, V_INT64VALUE_5,
                 V_INT64VALUE_5_LEN), "Int64Value{5}");
    CHECK(is_nil == false, "an int64 is never nil");
    OK();

    /* Int64Value{0} is omit-zero: a NON-nil, ZERO-LENGTH encoding. The
     * distinction from a nil leaf is the point of the flag; both hash to
     * H(0x00), which the Merkle test pins. */
    CHECK(cmt_pb_cdc_encode_int64(0, g_buf, sizeof(g_buf), &n, &is_nil)
          == CMT_OK, "Int64Value{0}");
    CHECK(n == 0, "Int64Value{0} is zero bytes");
    CHECK(is_nil == false, "Int64Value{0} is NOT nil");
    OK();

    CHECK(cmt_pb_cdc_encode_int64(-3, g_buf, sizeof(g_buf), &n, &is_nil)
          == CMT_OK, "Int64Value{-3}");
    CHECK(is_vec("Int64Value{-3}", g_buf, n, V_INT64VALUE_NEG,
                 V_INT64VALUE_NEG_LEN), "a negative int64 is ten bytes");
    OK();

    CHECK(cmt_pb_cdc_encode_string((const uint8_t *)"ab", 2, g_buf,
                                   sizeof(g_buf), &n, &is_nil) == CMT_OK,
          "StringValue");
    CHECK(is_vec("StringValue{ab}", g_buf, n, V_STRINGVALUE_AB,
                 V_STRINGVALUE_AB_LEN), "StringValue{ab}");
    CHECK(is_nil == false, "a non-empty string is not nil");
    OK();

    /* An empty string or byte slice is `isEmpty`, so cdcEncode returns
     * NIL — the leaf the header then hashes as H(0x00). */
    CHECK(cmt_pb_cdc_encode_string(NULL, 0, g_buf, sizeof(g_buf), &n,
                                   &is_nil) == CMT_OK, "StringValue{}");
    CHECK(n == 0 && is_nil == true, "an empty string is NIL");
    CHECK(cmt_pb_cdc_encode_bytes(NULL, 0, g_buf, sizeof(g_buf), &n,
                                  &is_nil) == CMT_OK, "BytesValue{}");
    CHECK(n == 0 && is_nil == true, "empty bytes are NIL");
    OK();

    CHECK(cmt_pb_cdc_encode_bytes(HASH_A, sizeof(HASH_A), g_buf,
                                  sizeof(g_buf), &n, &is_nil) == CMT_OK,
          "BytesValue{hash}");
    CHECK(is_digest("BytesValue{HASH_A}", g_buf, n, V_BYTESVALUE_HASH_A_LEN,
                    V_BYTESVALUE_HASH_A_SHA3), "BytesValue{HASH_A}");
    OK();
    return 0;
}

/* ══ the simple messages ═════════════════════════════════════════════ */

static int test_simple_messages(void)
{
    size_t n;

    /* version.Consensus — omit-zero on both fields (rule a). */
    {
        cmt_pb_consensus_t c;

        cmt_pb_consensus_init(&c);
        CHECK(cmt_pb_consensus_marshal(&c, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "Consensus{}");
        CHECK(n == 0, "Consensus{0,0} encodes to NOTHING");
        c.block = 11;
        CHECK(cmt_pb_consensus_marshal(&c, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "Consensus{11,0}");
        CHECK(is_vec("Consensus{11,0}", g_buf, n, V_CONSENSUS_11_0,
                     V_CONSENSUS_11_0_LEN), "app omitted when zero");
        c.app = 7;
        CHECK(cmt_pb_consensus_marshal(&c, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "Consensus{11,7}");
        CHECK(is_vec("Consensus{11,7}", g_buf, n, V_CONSENSUS_11_7,
                     V_CONSENSUS_11_7_LEN), "both fields");
        CHECK(cmt_pb_consensus_unmarshal(g_buf, n, &c) == CMT_OK, "decode");
        CHECK(c.block == 11 && c.app == 7, "round trip");
        OK();
    }

    /* PartSetHeader, and the CanonicalPartSetHeader that shares its shape. */
    {
        cmt_pb_part_set_header_t p;
        size_t                   n2;

        cmt_pb_part_set_header_init(&p);
        CHECK(cmt_pb_part_set_header_marshal(&p, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "psh zero");
        CHECK(n == 0, "PartSetHeader{0, empty} encodes to NOTHING");
        p.total = 7;
        memcpy(p.hash, HASH_A, sizeof(HASH_A));
        p.hash_len = sizeof(HASH_A);
        CHECK(cmt_pb_part_set_header_marshal(&p, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "psh A");
        CHECK(is_digest("PartSetHeader{7, HASH_A}", g_buf, n, V_PSH_A_LEN,
                        V_PSH_A_SHA3), "PartSetHeader");
        CHECK(cmt_pb_canonical_part_set_header_marshal(&p, g_buf2,
                                                       sizeof(g_buf2), &n2)
              == CMT_OK, "canonical psh");
        CHECK(is_vec("CanonicalPartSetHeader == PartSetHeader", g_buf2, n2,
                     g_buf, n), "the canonical form shares the shape");
        OK();

        cmt_pb_part_set_header_init(&p);
        CHECK(cmt_pb_part_set_header_unmarshal(g_buf, n, &p) == CMT_OK,
              "psh decode");
        CHECK(p.total == 7 && p.hash_len == 64 &&
              memcmp(p.hash, HASH_A, 64) == 0, "psh round trip");
        OK();
    }

    /* BlockID — rule (b): part_set_header is ALWAYS emitted, so a zero
     * BlockID is `12 00` and never empty. Every vote signs this. */
    {
        cmt_pb_block_id_t b;

        cmt_pb_block_id_init(&b);
        CHECK(cmt_pb_block_id_marshal(&b, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "blockid zero");
        CHECK(is_vec("BlockID{zero}", g_buf, n, V_BLOCKID_ZERO,
                     V_BLOCKID_ZERO_LEN),
              "a zero BlockID must be 12 00, NOT empty");
        OK();

        memcpy(b.hash, HASH_B, sizeof(HASH_B));
        b.hash_len = sizeof(HASH_B);
        b.part_set_header.total = 7;
        memcpy(b.part_set_header.hash, HASH_A, sizeof(HASH_A));
        b.part_set_header.hash_len = sizeof(HASH_A);
        CHECK(cmt_pb_block_id_marshal(&b, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "blockid A");
        CHECK(is_digest("BlockID{A}", g_buf, n, V_BLOCKID_A_LEN,
                        V_BLOCKID_A_SHA3), "BlockID{A}");
        cmt_pb_block_id_init(&b);
        CHECK(cmt_pb_block_id_unmarshal(g_buf, n, &b) == CMT_OK, "decode");
        CHECK(b.hash_len == 64 && memcmp(b.hash, HASH_B, 64) == 0, "hash");
        CHECK(b.part_set_header.total == 7, "psh total");
        CHECK(memcmp(b.part_set_header.hash, HASH_A, 64) == 0, "psh hash");
        OK();
    }

    /* HashedParams — the ConsensusHash preimage. MaxGas = -1 is the
     * ten-byte negative varint (rule g). */
    {
        cmt_pb_hashed_params_t h;

        cmt_pb_hashed_params_init(&h);
        CHECK(cmt_pb_hashed_params_marshal(&h, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "params zero");
        CHECK(n == 0, "HashedParams{0,0} encodes to NOTHING");
        h.block_max_bytes = 22020096;
        h.block_max_gas   = -1;
        CHECK(cmt_pb_hashed_params_marshal(&h, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "params default");
        CHECK(is_vec("HashedParams{22020096,-1}", g_buf, n,
                     V_HASHEDPARAMS_DEFAULT, V_HASHEDPARAMS_DEFAULT_LEN),
              "the golden HashedParams");
        cmt_pb_hashed_params_init(&h);
        CHECK(cmt_pb_hashed_params_unmarshal(g_buf, n, &h) == CMT_OK,
              "decode");
        CHECK(h.block_max_bytes == 22020096 && h.block_max_gas == -1,
              "round trip, including the negative");
        OK();
    }
    return 0;
}

/* ══ PublicKey (K-2) ═════════════════════════════════════════════════ */

static int test_public_key(void)
{
    cmt_pb_public_key_t k;
    size_t              n;

    cmt_pb_public_key_init(&k);
    CHECK(cmt_pb_public_key_marshal(&k, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "absent key");
    CHECK(n == 0, "a nil oneof writes nothing");
    OK();

    k.present = true;
    memcpy(k.key, KEY_FULL, sizeof(KEY_FULL));
    CHECK(cmt_pb_public_key_marshal(&k, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "branch 9");
    CHECK(g_buf[0] == 0x4a, "K-2: the tag byte must be 0x4a (field 9, wt 2)");
    CHECK(g_buf[1] == 0xa0 && g_buf[2] == 0x14,
          "the length must be uvarint(2592)");
    CHECK(is_digest("PublicKey{ML-DSA-87}", g_buf, n, V_PUBKEY_FULL_2592_LEN,
                    V_PUBKEY_FULL_2592_SHA3), "PublicKey branch 9");
    OK();

    cmt_pb_public_key_init(&k);
    CHECK(cmt_pb_public_key_unmarshal(g_buf, n, &k) == CMT_OK, "decode");
    CHECK(k.present, "present after decode");
    CHECK(memcmp(k.key, KEY_FULL, sizeof(KEY_FULL)) == 0, "key back");
    OK();

    /* K-2 refusals. Branches 1 and 2 stay in the pinned .proto but this
     * chain never writes them, and a wrong length is refused the way
     * crypto/encoding/codec.go:42-63 refuses a wrong key size. */
    CHECK(cmt_pb_public_key_unmarshal(V_PUBKEY_BRANCH1, V_PUBKEY_BRANCH1_LEN,
                                      &k) == CMT_REJECT,
          "ed25519 branch must REJECT");
    CHECK(cmt_pb_public_key_unmarshal(V_PUBKEY_BRANCH2, V_PUBKEY_BRANCH2_LEN,
                                      &k) == CMT_REJECT,
          "secp256k1 branch must REJECT");
    CHECK(cmt_pb_public_key_unmarshal(V_PUBKEY_BAD_LEN, V_PUBKEY_BAD_LEN_LEN,
                                      &k) == CMT_REJECT,
          "an 11-byte branch-9 key must REJECT");
    OK();

    /* 2591 and 2593 — one byte either side of the only accepted length. */
    {
        size_t   sizes[2] = { 2591, 2593 };
        unsigned s;

        for (s = 0; s < 2; s++) {
            uint8_t *b;
            size_t   total;
            size_t   off = 0;

            /* tag ‖ uvarint(len) ‖ len bytes, in an EXACT-SIZE heap buffer
             * so a one-byte over-read is visible to a sanitizer. */
            total = 1 + cmt_pb_uvarint_size(sizes[s]) + sizes[s];
            b = (uint8_t *)malloc(total);
            CHECK(b != NULL, "malloc");
            b[off++] = 0x4a;
            CHECK(cmt_pb_put_uvarint(b, total, &off, sizes[s]) == CMT_OK,
                  "len");
            memset(b + off, 0xAB, sizes[s]);
            CHECK(cmt_pb_public_key_unmarshal(b, total, &k) == CMT_REJECT,
                  "a key of the wrong length must REJECT");
            free(b);
        }
        OK();
    }

    /* Any OTHER field number is refused too, not skipped. */
    {
        static const uint8_t other_field[3] = { 0x18, 0x01, 0x00 };

        CHECK(cmt_pb_public_key_unmarshal(other_field, 2, &k) == CMT_REJECT,
              "an unknown PublicKey field must REJECT, not be skipped");
        OK();
    }
    return 0;
}

/* ══ SimpleValidator / Validator / ValidatorSet ══════════════════════ */

static int test_validators(void)
{
    size_t n;

    /* SimpleValidator — the ValidatorsHash leaf. pub_key is a POINTER, so
     * an absent key means the field is omitted entirely (rule a). */
    {
        cmt_pb_simple_validator_t sv;

        cmt_pb_simple_validator_init(&sv);
        CHECK(cmt_pb_simple_validator_marshal(&sv, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "sv zero");
        CHECK(n == 0, "SimpleValidator{nil, 0} encodes to NOTHING");

        sv.pub_key.present = true;
        memcpy(sv.pub_key.key, KEY_FULL, sizeof(KEY_FULL));
        sv.voting_power = 100;
        CHECK(cmt_pb_simple_validator_marshal(&sv, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "sv full");
        CHECK(is_digest("SimpleValidator", g_buf, n, V_SIMPLEVAL_FULL_LEN,
                        V_SIMPLEVAL_FULL_SHA3), "SimpleValidator");
        cmt_pb_simple_validator_init(&sv);
        CHECK(cmt_pb_simple_validator_unmarshal(g_buf, n, &sv) == CMT_OK,
              "sv decode");
        CHECK(sv.pub_key.present && sv.voting_power == 100, "sv round trip");
        OK();
    }

    /* Validator — pub_key is ALWAYS here (rule b), so a zero Validator is
     * `12 00`, not empty. That is the difference from SimpleValidator and
     * it changes the bytes. */
    {
        cmt_pb_validator_t v;

        cmt_pb_validator_init(&v);
        CHECK(cmt_pb_validator_marshal(&v, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "validator zero");
        CHECK(is_vec("Validator{zero}", g_buf, n, V_VALIDATOR_ZERO,
                     V_VALIDATOR_ZERO_LEN),
              "a zero Validator must still emit its pub_key field");

        memcpy(v.address, ADDR_A, sizeof(ADDR_A));
        v.address_len = sizeof(ADDR_A);
        v.pub_key.present = true;
        memcpy(v.pub_key.key, KEY_FULL, sizeof(KEY_FULL));
        v.voting_power = 100;
        v.proposer_priority = -5;
        CHECK(cmt_pb_validator_marshal(&v, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "validator full");
        CHECK(is_digest("Validator", g_buf, n, V_VALIDATOR_FULL_LEN,
                        V_VALIDATOR_FULL_SHA3), "Validator");
        cmt_pb_validator_init(&v);
        CHECK(cmt_pb_validator_unmarshal(g_buf, n, &v) == CMT_OK, "decode");
        CHECK(v.address_len == 32 && memcmp(v.address, ADDR_A, 32) == 0,
              "address back");
        CHECK(v.voting_power == 100 && v.proposer_priority == -5,
              "a negative proposer priority survives");
        OK();
    }

    /* ValidatorSet — a repeated message plus a pointer field. */
    {
        cmt_pb_validator_set_t vs;
        static cmt_pb_validator_t slots[4];

        memset(&vs, 0, sizeof(vs));
        vs.validators     = slots;
        vs.validators_cap = 4;
        cmt_pb_validator_set_init(&vs);
        CHECK(cmt_pb_validator_set_marshal(&vs, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "vs empty");
        CHECK(n == 0, "an empty ValidatorSet encodes to NOTHING");

        cmt_pb_validator_init(&slots[0]);
        memcpy(slots[0].address, ADDR_A, 32);
        slots[0].address_len = 32;
        slots[0].pub_key.present = true;
        memcpy(slots[0].pub_key.key, KEY_FULL, sizeof(KEY_FULL));
        slots[0].voting_power = 100;
        slots[0].proposer_priority = -5;

        cmt_pb_validator_init(&slots[1]);
        memcpy(slots[1].address, ADDR_B, 32);
        slots[1].address_len = 32;
        slots[1].pub_key.present = true;
        memcpy(slots[1].pub_key.key, KEY_FULL, sizeof(KEY_FULL));
        slots[1].voting_power = 50;
        slots[1].proposer_priority = 5;

        vs.validators_len = 2;
        vs.has_proposer = true;
        vs.proposer = slots[0];
        vs.total_voting_power = 150;
        CHECK(cmt_pb_validator_set_marshal(&vs, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "vs 2");
        CHECK(is_digest("ValidatorSet{2}", g_buf, n, V_VALSET_2_LEN,
                        V_VALSET_2_SHA3), "ValidatorSet");
        OK();

        /* Round trip through the caller's storage. */
        {
            static cmt_pb_validator_t back_slots[4];
            cmt_pb_validator_set_t    back;
            size_t                    n2;

            memset(&back, 0, sizeof(back));
            back.validators     = back_slots;
            back.validators_cap = 4;
            CHECK(cmt_pb_validator_set_unmarshal(g_buf, n, &back) == CMT_OK,
                  "vs decode");
            CHECK(back.validators_len == 2, "two validators back");
            CHECK(back.has_proposer, "proposer back");
            CHECK(back.total_voting_power == 150, "total back");
            CHECK(back.validators[1].voting_power == 50, "order preserved");
            CHECK(cmt_pb_validator_set_marshal(&back, g_buf2,
                                               sizeof(g_buf2), &n2)
                  == CMT_OK, "re-marshal");
            CHECK(is_vec("ValidatorSet round trip", g_buf2, n2, g_buf, n),
                  "decode then encode must reproduce the bytes");
            OK();
        }

        /* A list longer than the caller's capacity is REFUSED, never
         * written past (INVARIANT). One slot, two validators on the wire. */
        {
            static cmt_pb_validator_t one_slot[1];
            cmt_pb_validator_set_t    tight;

            memset(&tight, 0, sizeof(tight));
            tight.validators     = one_slot;
            tight.validators_cap = 1;
            CHECK(cmt_pb_validator_set_unmarshal(g_buf, n, &tight)
                  == CMT_REJECT,
                  "a list past the caller's capacity must REJECT");
            OK();
        }
    }
    return 0;
}

/* ══ Header ══════════════════════════════════════════════════════════ */

static int test_header(void)
{
    static cmt_pb_header_t h;
    size_t                 n;
    size_t                 n2;

    cmt_pb_header_init(&h);
    CHECK(h.time.seconds == CMT_TIME_MIN_SECONDS,
          "a fresh Header carries Go's zero time");
    CHECK(cmt_pb_header_marshal(&h, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "header zero");
    CHECK(is_vec("Header{zero}", g_buf, n, V_HEADER_ZERO, V_HEADER_ZERO_LEN),
          "an all-zero Header is NINETEEN bytes: version, time and "
          "last_block_id are always emitted");
    OK();

    h.version.block = 11;
    h.version.app   = 3;
    memcpy(h.chain_id, CHAIN, sizeof(CHAIN));
    h.chain_id_len = sizeof(CHAIN);
    h.height = 42;
    h.time   = TS_A;
    memcpy(h.last_block_id.hash, HASH_B, 64);
    h.last_block_id.hash_len = 64;
    h.last_block_id.part_set_header.total = 7;
    memcpy(h.last_block_id.part_set_header.hash, HASH_A, 64);
    h.last_block_id.part_set_header.hash_len = 64;
    memcpy(h.last_commit_hash, HASH_A, 64);      h.last_commit_hash_len = 64;
    memcpy(h.data_hash, HASH_B, 64);             h.data_hash_len = 64;
    memcpy(h.validators_hash, HASH_C, 64);       h.validators_hash_len = 64;
    memcpy(h.next_validators_hash, HASH_A, 64);  h.next_validators_hash_len = 64;
    memcpy(h.consensus_hash, HASH_B, 64);        h.consensus_hash_len = 64;
    memcpy(h.app_hash, HASH_C, 64);              h.app_hash_len = 64;
    memcpy(h.last_results_hash, HASH_A, 64);     h.last_results_hash_len = 64;
    memcpy(h.evidence_hash, HASH_B, 64);         h.evidence_hash_len = 64;
    memcpy(h.proposer_address, ADDR_A, 32);      h.proposer_address_len = 32;

    CHECK(cmt_pb_header_marshal(&h, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "header full");
    CHECK(is_digest("Header{full}", g_buf, n, V_HEADER_FULL_LEN,
                    V_HEADER_FULL_SHA3), "Header");
    OK();

    /* Round trip: every one of the fourteen fields must survive. */
    {
        static cmt_pb_header_t back;

        CHECK(cmt_pb_header_unmarshal(g_buf, n, &back) == CMT_OK, "decode");
        CHECK(back.version.block == 11 && back.version.app == 3, "version");
        CHECK(back.height == 42, "height");
        CHECK(back.time.seconds == TS_A.seconds &&
              back.time.nanos == TS_A.nanos, "time");
        CHECK(back.chain_id_len == 32 &&
              memcmp(back.chain_id, CHAIN, 32) == 0, "chain id");
        CHECK(back.last_block_id.part_set_header.total == 7, "last block id");
        CHECK(back.proposer_address_len == 32 &&
              memcmp(back.proposer_address, ADDR_A, 32) == 0, "proposer");
        CHECK(cmt_pb_header_marshal(&back, g_buf2, sizeof(g_buf2), &n2)
              == CMT_OK, "re-marshal");
        CHECK(is_vec("Header round trip", g_buf2, n2, g_buf, n),
              "decode then encode must reproduce the bytes");
        OK();
    }

    /* A field longer than its destination is REFUSED. A 65-byte
     * validators_hash cannot be stored in a 64-byte field, and silently
     * truncating it would change what gets hashed. */
    {
        uint8_t *b;
        size_t   total = 3 + 65;
        size_t   off = 0;

        b = (uint8_t *)malloc(total);
        CHECK(b != NULL, "malloc");
        b[off++] = 0x42;                  /* field 8, wire type 2 */
        CHECK(cmt_pb_put_uvarint(b, total, &off, 65) == CMT_OK, "len");
        memset(b + off, 0xCD, 65);
        CHECK(cmt_pb_header_unmarshal(b, off + 65, &h) == CMT_REJECT,
              "a 65-byte hash must REJECT, never truncate");
        free(b);
        OK();
    }

    /* An UNKNOWN field is SKIPPED, not refused — being stricter than the
     * generated decoder is as wrong as being looser. Field 99, varint. */
    {
        uint8_t  b[8];
        size_t   off = 0;

        b[off++] = 0x98;                  /* tag for field 99, wire type 0 */
        b[off++] = 0x06;
        b[off++] = 0x2a;                  /* its varint value, 42 */
        CHECK(cmt_pb_header_unmarshal(b, off, &h) == CMT_OK,
              "an unknown field must be SKIPPED");
        CHECK(h.height == 0, "and must leave the known fields alone");
        OK();
    }

    /* A wrong wire type on a KNOWN field is refused, as the generated
     * decoder refuses it. Height (field 3) as length-delimited. */
    {
        static const uint8_t b[3] = { 0x1a, 0x01, 0x00 };

        CHECK(cmt_pb_header_unmarshal(b, sizeof(b), &h) == CMT_REJECT,
              "a wrong wire type on a known field must REJECT");
        OK();
    }
    return 0;
}

/* ══ Vote / CommitSig / Commit / Proposal ════════════════════════════ */

static int test_vote_commit_proposal(void)
{
    size_t n;
    size_t n2;

    /* Vote — fields 4 and 5 are ALWAYS emitted, so a zero Vote is
     * seventeen bytes: an empty BlockID and Go's zero time. */
    {
        static cmt_pb_vote_t v;
        static cmt_pb_vote_t back;
        uint8_t ext[4];

        cmt_pb_vote_init(&v);
        CHECK(cmt_pb_vote_marshal(&v, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "vote zero");
        CHECK(is_vec("Vote{zero}", g_buf, n, V_VOTE_ZERO, V_VOTE_ZERO_LEN),
              "a zero Vote is seventeen bytes, not zero");
        OK();

        pat(ext, sizeof(ext), 0xA0);
        v.type   = CMT_PB_MSG_TYPE_PRECOMMIT;
        v.height = 42;
        v.round  = 1;
        memcpy(v.block_id.hash, HASH_B, 64);
        v.block_id.hash_len = 64;
        v.block_id.part_set_header.total = 7;
        memcpy(v.block_id.part_set_header.hash, HASH_A, 64);
        v.block_id.part_set_header.hash_len = 64;
        v.timestamp = TS_A;
        memcpy(v.validator_address, ADDR_A, 32);
        v.validator_address_len = 32;
        v.validator_index = 3;
        memcpy(v.signature, SIG_S, sizeof(SIG_S));
        v.signature_len = sizeof(SIG_S);
        v.extension.data = ext;
        v.extension.len  = sizeof(ext);
        {
            static uint8_t extsig[6];

            pat(extsig, sizeof(extsig), 0xA1);
            memcpy(v.extension_signature, extsig, sizeof(extsig));
            v.extension_signature_len = sizeof(extsig);
        }
        CHECK(cmt_pb_vote_marshal(&v, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "vote short");
        CHECK(is_digest("Vote{short sig}", g_buf, n, V_VOTE_SHORT_LEN,
                        V_VOTE_SHORT_SHA3), "Vote");
        OK();

        arena_reset();
        CHECK(cmt_pb_vote_unmarshal(g_buf, n, &back, &g_arena) == CMT_OK,
              "vote decode");
        CHECK(back.type == CMT_PB_MSG_TYPE_PRECOMMIT, "type");
        CHECK(back.height == 42 && back.round == 1, "height/round");
        CHECK(back.validator_index == 3, "index");
        CHECK(back.signature_len == sizeof(SIG_S), "sig len");
        CHECK(back.extension.len == sizeof(ext), "extension len");
        /* The decoded extension must point into the ARENA, not the input. */
        CHECK(back.extension.data >= g_arena_bytes &&
              back.extension.data < g_arena_bytes + sizeof(g_arena_bytes),
              "a decoded payload must live in the caller's arena");
        CHECK(cmt_pb_vote_marshal(&back, g_buf2, sizeof(g_buf2), &n2)
              == CMT_OK, "re-marshal");
        CHECK(is_vec("Vote round trip", g_buf2, n2, g_buf, n), "round trip");
        OK();

        /* The input buffer is overwritten; the decoded values must not
         * change, which is the no-pointer-into-the-input contract. */
        memset(g_buf, 0xEE, n);
        CHECK(back.extension.len == sizeof(ext), "len after overwrite");
        CHECK(memcmp(back.extension.data, ext, sizeof(ext)) == 0,
              "the decoded extension must survive the input being wiped");
        CHECK(memcmp(back.validator_address, ADDR_A, 32) == 0,
              "the decoded address must survive too");
        OK();

        /* The real signature sizes. */
        v.extension.data = ext;
        v.extension.len  = sizeof(ext);
        memcpy(v.signature, SIG_FULL, sizeof(SIG_FULL));
        v.signature_len = sizeof(SIG_FULL);
        memcpy(v.extension_signature, SIG_FULL, sizeof(SIG_FULL));
        v.extension_signature_len = sizeof(SIG_FULL);
        CHECK(cmt_pb_vote_marshal(&v, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "vote full sig");
        CHECK(is_digest("Vote{4627-byte signatures}", g_buf, n,
                        V_VOTE_FULLSIG_LEN, V_VOTE_FULLSIG_SHA3), "Vote");
        OK();
    }

    /* CommitSig — the Absent entry is the case D-19 rev 6 item 4 turns on. */
    {
        cmt_pb_commit_sig_t cs;

        cmt_pb_commit_sig_init(&cs);
        cs.block_id_flag = CMT_PB_BLOCK_ID_FLAG_ABSENT;
        CHECK(cmt_pb_commit_sig_marshal(&cs, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "absent");
        CHECK(is_vec("CommitSig{Absent}", g_buf, n, V_COMMITSIG_ABSENT,
                     V_COMMITSIG_ABSENT_LEN),
              "an Absent CommitSig is FIFTEEN bytes — its zero timestamp "
              "is still written");
        OK();

        cs.block_id_flag = CMT_PB_BLOCK_ID_FLAG_COMMIT;
        memcpy(cs.validator_address, ADDR_A, 32);
        cs.validator_address_len = 32;
        cs.timestamp = TS_A;
        memcpy(cs.signature, SIG_S, sizeof(SIG_S));
        cs.signature_len = sizeof(SIG_S);
        CHECK(cmt_pb_commit_sig_marshal(&cs, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "commit sig");
        CHECK(is_digest("CommitSig{Commit}", g_buf, n,
                        V_COMMITSIG_COMMIT_LEN, V_COMMITSIG_COMMIT_SHA3),
              "CommitSig");
        cmt_pb_commit_sig_init(&cs);
        CHECK(cmt_pb_commit_sig_unmarshal(g_buf, n, &cs) == CMT_OK,
              "decode");
        CHECK(cs.block_id_flag == CMT_PB_BLOCK_ID_FLAG_COMMIT, "flag");
        CHECK(cs.timestamp.seconds == TS_A.seconds, "timestamp");
        OK();
    }

    /* Commit — a repeated message with all three flags present. */
    {
        cmt_pb_commit_t c;
        static cmt_pb_commit_sig_t sigs[4];
        static cmt_pb_commit_sig_t back_sigs[4];
        cmt_pb_commit_t back;

        memset(&c, 0, sizeof(c));
        c.signatures     = sigs;
        c.signatures_cap = 4;
        cmt_pb_commit_init(&c);
        CHECK(cmt_pb_commit_marshal(&c, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "commit zero");
        CHECK(is_vec("Commit{zero}", g_buf, n, V_COMMIT_ZERO,
                     V_COMMIT_ZERO_LEN),
              "a zero Commit still carries its BlockID field");
        OK();

        cmt_pb_commit_sig_init(&sigs[0]);
        sigs[0].block_id_flag = CMT_PB_BLOCK_ID_FLAG_ABSENT;

        cmt_pb_commit_sig_init(&sigs[1]);
        sigs[1].block_id_flag = CMT_PB_BLOCK_ID_FLAG_COMMIT;
        memcpy(sigs[1].validator_address, ADDR_A, 32);
        sigs[1].validator_address_len = 32;
        sigs[1].timestamp = TS_A;
        memcpy(sigs[1].signature, SIG_S, sizeof(SIG_S));
        sigs[1].signature_len = sizeof(SIG_S);

        cmt_pb_commit_sig_init(&sigs[2]);
        sigs[2].block_id_flag = CMT_PB_BLOCK_ID_FLAG_NIL;
        memcpy(sigs[2].validator_address, ADDR_B, 32);
        sigs[2].validator_address_len = 32;
        sigs[2].timestamp = TS_A;
        memcpy(sigs[2].signature, SIG_S, sizeof(SIG_S));
        sigs[2].signature_len = sizeof(SIG_S);

        c.height = 42;
        c.round  = 1;
        memcpy(c.block_id.hash, HASH_B, 64);
        c.block_id.hash_len = 64;
        c.block_id.part_set_header.total = 7;
        memcpy(c.block_id.part_set_header.hash, HASH_A, 64);
        c.block_id.part_set_header.hash_len = 64;
        c.signatures_len = 3;
        CHECK(cmt_pb_commit_marshal(&c, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "commit 3");
        CHECK(is_digest("Commit{Absent,Commit,Nil}", g_buf, n,
                        V_COMMIT_3SIGS_LEN, V_COMMIT_3SIGS_SHA3), "Commit");
        OK();

        memset(&back, 0, sizeof(back));
        back.signatures     = back_sigs;
        back.signatures_cap = 4;
        CHECK(cmt_pb_commit_unmarshal(g_buf, n, &back) == CMT_OK, "decode");
        CHECK(back.signatures_len == 3, "three signatures back");
        CHECK(back.signatures[0].block_id_flag ==
              CMT_PB_BLOCK_ID_FLAG_ABSENT, "flag 0");
        CHECK(back.signatures[1].block_id_flag ==
              CMT_PB_BLOCK_ID_FLAG_COMMIT, "flag 1");
        CHECK(back.signatures[2].block_id_flag ==
              CMT_PB_BLOCK_ID_FLAG_NIL, "flag 2");
        CHECK(back.signatures[0].timestamp.seconds == CMT_TIME_MIN_SECONDS,
              "the Absent entry's timestamp is Go's zero, not 1970");
        CHECK(cmt_pb_commit_marshal(&back, g_buf2, sizeof(g_buf2), &n2)
              == CMT_OK, "re-marshal");
        CHECK(is_vec("Commit round trip", g_buf2, n2, g_buf, n),
              "round trip, order preserved");
        OK();

        /* More signatures than the caller's slots is REFUSED. */
        {
            cmt_pb_commit_t tight;
            static cmt_pb_commit_sig_t two[2];

            memset(&tight, 0, sizeof(tight));
            tight.signatures     = two;
            tight.signatures_cap = 2;
            CHECK(cmt_pb_commit_unmarshal(g_buf, n, &tight) == CMT_REJECT,
                  "three signatures into two slots must REJECT");
            OK();
        }
    }

    /* Proposal */
    {
        cmt_pb_proposal_t p;

        cmt_pb_proposal_init(&p);
        CHECK(cmt_pb_proposal_marshal(&p, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "proposal zero");
        CHECK(is_vec("Proposal{zero}", g_buf, n, V_PROPOSAL_ZERO,
                     V_PROPOSAL_ZERO_LEN), "a zero Proposal");
        p.type = CMT_PB_MSG_TYPE_PROPOSAL;
        p.height = 42;
        p.round = 1;
        p.pol_round = -1;
        memcpy(p.block_id.hash, HASH_B, 64);
        p.block_id.hash_len = 64;
        p.block_id.part_set_header.total = 7;
        memcpy(p.block_id.part_set_header.hash, HASH_A, 64);
        p.block_id.part_set_header.hash_len = 64;
        p.timestamp = TS_A;
        memcpy(p.signature, SIG_S, sizeof(SIG_S));
        p.signature_len = sizeof(SIG_S);
        CHECK(cmt_pb_proposal_marshal(&p, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "proposal A");
        CHECK(is_digest("Proposal", g_buf, n, V_PROPOSAL_A_LEN,
                        V_PROPOSAL_A_SHA3), "Proposal");
        cmt_pb_proposal_init(&p);
        CHECK(cmt_pb_proposal_unmarshal(g_buf, n, &p) == CMT_OK, "decode");
        CHECK(p.pol_round == -1, "a POL round of -1 survives");
        CHECK(p.type == CMT_PB_MSG_TYPE_PROPOSAL, "type 32");
        OK();
    }
    return 0;
}

/* ══ canonical (sign bytes) ══════════════════════════════════════════ */

static int test_canonical(void)
{
    size_t n;
    size_t n2;

    /* The REV 3.2 golden CanonicalVote. Note there is NO round tag: round
     * is zero and sfixed64 is omit-zero like any other scalar. */
    {
        cmt_pb_canonical_vote_t cv;

        cmt_pb_canonical_vote_init(&cv);
        cv.type   = CMT_PB_MSG_TYPE_PRECOMMIT;
        cv.height = 1;
        cv.round  = 0;
        cv.has_block_id = false;         /* CanonicalizeBlockID's nil */
        cv.chain_id[0] = 'a';
        cv.chain_id[1] = 'b';
        cv.chain_id_len = 2;
        CHECK(cmt_pb_canonical_vote_marshal(&cv, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "canonical vote golden");
        CHECK(is_vec("CanonicalVote{golden}", g_buf, n, V_CANONVOTE_GOLDEN,
                     V_CANONVOTE_GOLDEN_LEN), "the REV 3.2 golden vector");
        CHECK(n == 28, "28 bytes");
        /* Height is a LITTLE-endian sfixed64 under tag 0x11. */
        CHECK(g_buf[2] == 0x11, "height tag is 0x11 (field 2, fixed64)");
        CHECK(g_buf[3] == 0x01 && g_buf[10] == 0x00,
              "height 1 is little-endian: 01 00 00 00 00 00 00 00");
        OK();

        /* Round 1 adds the 0x19 tag; round 0 has none. */
        cv.round = 1;
        CHECK(cmt_pb_canonical_vote_marshal(&cv, g_buf2, sizeof(g_buf2), &n2)
              == CMT_OK, "round 1");
        CHECK(n2 == n + 9, "a non-zero round adds a tag and eight bytes");
        CHECK(g_buf2[11] == 0x19, "round tag is 0x19");
        cv.round = 0;
        OK();

        /* Round trip, and the same through MarshalDelimited. */
        CHECK(cmt_pb_canonical_vote_unmarshal(V_CANONVOTE_GOLDEN,
                                              V_CANONVOTE_GOLDEN_LEN, &cv)
              == CMT_OK, "decode golden");
        CHECK(cv.height == 1 && cv.round == 0, "height/round back");
        CHECK(cv.has_block_id == false, "the nil BlockID stays absent");
        CHECK(cv.chain_id_len == 2, "chain id back");
        CHECK(cv.timestamp.seconds == CMT_TIME_MIN_SECONDS, "zero time back");
        CHECK(cmt_pb_canonical_vote_marshal(&cv, g_buf2, sizeof(g_buf2), &n2)
              == CMT_OK, "re-marshal");
        CHECK(is_vec("CanonicalVote round trip", g_buf2, n2,
                     V_CANONVOTE_GOLDEN, V_CANONVOTE_GOLDEN_LEN),
              "round trip");
        OK();

        /* With a BlockID present. */
        cmt_pb_canonical_vote_init(&cv);
        cv.type   = CMT_PB_MSG_TYPE_PRECOMMIT;
        cv.height = 42;
        cv.round  = 1;
        cv.has_block_id = true;
        memcpy(cv.block_id.hash, HASH_B, 64);
        cv.block_id.hash_len = 64;
        cv.block_id.part_set_header.total = 7;
        memcpy(cv.block_id.part_set_header.hash, HASH_A, 64);
        cv.block_id.part_set_header.hash_len = 64;
        cv.timestamp = TS_A;
        memcpy(cv.chain_id, CHAIN, 32);
        cv.chain_id_len = 32;
        CHECK(cmt_pb_canonical_vote_marshal(&cv, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "canonical vote full");
        CHECK(is_digest("CanonicalVote{full}", g_buf, n, V_CANONVOTE_FULL_LEN,
                        V_CANONVOTE_FULL_SHA3), "CanonicalVote");
        OK();
    }

    /* CanonicalProposal — its pol_round is an INT64 varint (field 4),
     * unlike types.Proposal's int32. */
    {
        cmt_pb_canonical_proposal_t cp;

        cmt_pb_canonical_proposal_init(&cp);
        cp.type   = CMT_PB_MSG_TYPE_PROPOSAL;
        cp.height = 1;
        cp.round  = 0;
        cp.pol_round = 0;
        cp.has_block_id = false;
        cp.chain_id[0] = 'a';
        cp.chain_id[1] = 'b';
        cp.chain_id_len = 2;
        CHECK(cmt_pb_canonical_proposal_marshal(&cp, g_buf, sizeof(g_buf),
                                                &n) == CMT_OK, "cp nil bid");
        CHECK(is_vec("CanonicalProposal{nil BlockID}", g_buf, n,
                     V_CANONPROPOSAL_NILBID, V_CANONPROPOSAL_NILBID_LEN),
              "a nil canonical BlockID is absent entirely");
        OK();

        cp.height = 42;
        cp.round  = 1;
        cp.pol_round = -1;
        cp.has_block_id = true;
        memcpy(cp.block_id.hash, HASH_B, 64);
        cp.block_id.hash_len = 64;
        cp.block_id.part_set_header.total = 7;
        memcpy(cp.block_id.part_set_header.hash, HASH_A, 64);
        cp.block_id.part_set_header.hash_len = 64;
        cp.timestamp = TS_A;
        memcpy(cp.chain_id, CHAIN, 32);
        cp.chain_id_len = 32;
        CHECK(cmt_pb_canonical_proposal_marshal(&cp, g_buf, sizeof(g_buf),
                                                &n) == CMT_OK, "cp full");
        CHECK(is_digest("CanonicalProposal", g_buf, n,
                        V_CANONPROPOSAL_A_LEN, V_CANONPROPOSAL_A_SHA3),
              "CanonicalProposal");
        cmt_pb_canonical_proposal_init(&cp);
        CHECK(cmt_pb_canonical_proposal_unmarshal(g_buf, n, &cp) == CMT_OK,
              "decode");
        CHECK(cp.pol_round == -1, "a negative POL round survives");
        CHECK(cp.has_block_id, "the BlockID came back");
        OK();
    }

    /* CanonicalVoteExtension — no ALWAYS field at all, so an empty one is
     * genuinely empty. */
    {
        cmt_pb_canonical_vote_extension_t cve;
        uint8_t ext[6];

        cmt_pb_canonical_vote_extension_init(&cve);
        CHECK(cmt_pb_canonical_vote_extension_marshal(&cve, g_buf,
                                                      sizeof(g_buf), &n)
              == CMT_OK, "cve zero");
        CHECK(n == 0,
              "CanonicalVoteExtension has no always-emitted field");
        pat(ext, sizeof(ext), 0xB0);
        cve.extension.data = ext;
        cve.extension.len  = sizeof(ext);
        cve.height = 42;
        cve.round  = 1;
        memcpy(cve.chain_id, CHAIN, 32);
        cve.chain_id_len = 32;
        CHECK(cmt_pb_canonical_vote_extension_marshal(&cve, g_buf,
                                                      sizeof(g_buf), &n)
              == CMT_OK, "cve A");
        CHECK(is_digest("CanonicalVoteExtension", g_buf, n,
                        V_CANONVOTEEXT_A_LEN, V_CANONVOTEEXT_A_SHA3), "cve");
        arena_reset();
        CHECK(cmt_pb_canonical_vote_extension_unmarshal(g_buf, n, &cve,
                                                        &g_arena) == CMT_OK,
              "decode");
        CHECK(cve.height == 42 && cve.round == 1, "height/round");
        CHECK(cve.extension.len == sizeof(ext), "extension");
        OK();
    }
    return 0;
}

/* ══ Proof / Part ════════════════════════════════════════════════════ */

static int test_proof_and_part(void)
{
    size_t n;
    size_t n2;

    {
        static cmt_proof_t p;
        static cmt_proof_t back;

        cmt_pb_proof_init(&p);
        CHECK(cmt_pb_proof_marshal(&p, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "proof zero");
        CHECK(n == 0, "an all-zero Proof encodes to NOTHING");

        p.total = 8;
        p.index = 3;
        memcpy(p.leaf_hash, HASH_A, 64);
        p.leaf_hash_len = 64;
        memcpy(p.aunts[0], HASH_B, 64); p.aunt_len[0] = 64;
        memcpy(p.aunts[1], HASH_C, 64); p.aunt_len[1] = 64;
        memcpy(p.aunts[2], HASH_A, 64); p.aunt_len[2] = 64;
        p.aunts_len = 3;
        CHECK(cmt_pb_proof_marshal(&p, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "proof 3 aunts");
        CHECK(is_digest("Proof{3 aunts}", g_buf, n, V_PROOF_3AUNTS_LEN,
                        V_PROOF_3AUNTS_SHA3), "Proof");
        OK();

        /* cmt_proof_from_proto ends in ValidateBasic (proof.go:160). */
        CHECK(cmt_proof_from_proto(g_buf, n, &back) == CMT_OK, "from_proto");
        CHECK(back.total == 8 && back.index == 3, "scalars");
        CHECK(back.aunts_len == 3, "aunt count");
        CHECK(memcmp(back.aunts[1], HASH_C, 64) == 0, "aunt ORDER preserved");
        CHECK(cmt_pb_proof_marshal(&back, g_buf2, sizeof(g_buf2), &n2)
              == CMT_OK, "re-marshal");
        CHECK(is_vec("Proof round trip", g_buf2, n2, g_buf, n), "round trip");
        /* ToProto is the identity (proof.go:134-146). */
        CHECK(cmt_proof_to_proto(&p, &back) == CMT_OK, "to_proto");
        CHECK(memcmp(&back, &p, sizeof(p)) == 0, "ToProto is the identity");
        OK();

        /* DELTA 1 — an EMPTY aunt is one element on the wire, `22 00`.
         * crypto/proof.pb.go:373-381 guards only the SLICE, never the
         * element, so a zero-length aunt is written out, not omitted.
         * The hashes here are deliberately short: this exercises the
         * CODEC, and the message is one the reference's own ValidateBasic
         * would refuse (an aunt must be tmhash-sized), which is asserted
         * below — codec accepts the bytes, validation rejects the value. */
        {
            static cmt_proof_t e;
            static cmt_proof_t e_back;

            cmt_pb_proof_init(&e);
            e.total = 2;
            e.index = 0;
            pat(e.leaf_hash, 2, 0xB0);
            e.leaf_hash_len = 2;
            e.aunt_len[0] = 0;                 /* the empty aunt */
            pat(e.aunts[1], 3, 0xB1);
            e.aunt_len[1] = 3;
            e.aunts_len = 2;
            CHECK(cmt_pb_proof_marshal(&e, g_buf, sizeof(g_buf), &n)
                  == CMT_OK, "proof with an empty aunt");
            CHECK(is_vec("Proof{empty aunt}", g_buf, n,
                         V_PROOF_EMPTY_AUNT, V_PROOF_EMPTY_AUNT_LEN),
                  "an empty aunt is `22 00`, not an omission");
            OK();

            /* It decodes back to TWO aunts, the first of length 0. */
            cmt_pb_proof_init(&e_back);
            CHECK(cmt_pb_proof_unmarshal(g_buf, n, &e_back) == CMT_OK,
                  "decode");
            CHECK(e_back.aunts_len == 2, "two aunts back, the empty one too");
            CHECK(e_back.aunt_len[0] == 0, "the first aunt is empty");
            CHECK(e_back.aunt_len[1] == 3, "order preserved");
            CHECK(cmt_pb_proof_marshal(&e_back, g_buf2, sizeof(g_buf2), &n2)
                  == CMT_OK, "re-marshal");
            CHECK(is_vec("Proof{empty aunt} round trip", g_buf2, n2,
                         g_buf, n), "round trip");
            /* Same bytes, but the VALUE is invalid: ValidateBasic checks
             * the leaf hash first (proof.go:120-122) and then every aunt
             * (:126-130); this message fails both. */
            CHECK(cmt_proof_from_proto(g_buf, n, &e_back) == CMT_REJECT,
                  "ValidateBasic refuses these under-sized hashes");
            OK();
        }

        /* from_proto refuses what ValidateBasic refuses: a 63-byte leaf
         * hash decodes fine as a codec matter but fails validation. */
        {
            uint8_t  b[3 + 63];
            size_t   off = 0;

            b[off++] = 0x1a;              /* field 3, wire type 2 */
            CHECK(cmt_pb_put_uvarint(b, sizeof(b), &off, 63) == CMT_OK, "l");
            memset(b + off, 0x77, 63);
            CHECK(cmt_pb_proof_unmarshal(b, off + 63, &back) == CMT_OK,
                  "the codec accepts a short leaf hash");
            CHECK(back.leaf_hash_len == 63, "and records its length");
            CHECK(cmt_proof_from_proto(b, off + 63, &back) == CMT_REJECT,
                  "but ProofFromProto's ValidateBasic must REJECT it");
            OK();
        }

        /* 101 aunts: refused at the message boundary. */
        {
            uint8_t *b;
            size_t   total = 101 * (2 + 64);
            size_t   off = 0;
            int      k;

            b = (uint8_t *)malloc(total);
            CHECK(b != NULL, "malloc");
            for (k = 0; k < 101; k++) {
                b[off++] = 0x22;          /* field 4, wire type 2 */
                b[off++] = 64;
                memset(b + off, (uint8_t)k, 64);
                off += 64;
            }
            CHECK(off == total, "built 101 aunts");
            CHECK(cmt_pb_proof_unmarshal(b, total, &back) == CMT_REJECT,
                  "101 aunts must REJECT");
            /* 100 is the boundary and must pass. */
            CHECK(cmt_pb_proof_unmarshal(b, 100 * 66, &back) == CMT_OK,
                  "100 aunts must pass");
            CHECK(back.aunts_len == 100, "100 recorded");
            free(b);
            OK();
        }
    }

    /* Part — its proof is ALWAYS emitted, so a zero Part is `1a 00`. */
    {
        static cmt_pb_part_t part;
        static cmt_pb_part_t back;
        uint8_t              payload[5];

        cmt_pb_part_init(&part);
        CHECK(cmt_pb_part_marshal(&part, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "part zero");
        CHECK(is_vec("Part{zero}", g_buf, n, V_PART_ZERO, V_PART_ZERO_LEN),
              "a zero Part still carries its proof field");

        pat(payload, sizeof(payload), 0x80);
        part.index = 2;
        part.bytes.data = payload;
        part.bytes.len  = sizeof(payload);
        part.proof.total = 4;
        part.proof.index = 2;
        memcpy(part.proof.leaf_hash, HASH_A, 64);
        part.proof.leaf_hash_len = 64;
        memcpy(part.proof.aunts[0], HASH_B, 64);
        part.proof.aunt_len[0] = 64;
        part.proof.aunts_len = 1;
        CHECK(cmt_pb_part_marshal(&part, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "part A");
        CHECK(is_digest("Part", g_buf, n, V_PART_A_LEN, V_PART_A_SHA3),
              "Part");
        arena_reset();
        CHECK(cmt_pb_part_unmarshal(g_buf, n, &back, &g_arena) == CMT_OK,
              "decode");
        CHECK(back.index == 2 && back.bytes.len == sizeof(payload), "part");
        CHECK(back.proof.aunts_len == 1, "the embedded proof came back");
        CHECK(cmt_pb_part_marshal(&back, g_buf2, sizeof(g_buf2), &n2)
              == CMT_OK, "re-marshal");
        CHECK(is_vec("Part round trip", g_buf2, n2, g_buf, n), "round trip");
        OK();
    }
    return 0;
}

/* ══ Data / ExecTxResult / Evidence ══════════════════════════════════ */

static int test_data_results_evidence(void)
{
    size_t n;
    size_t n2;

    /* Data — three txs, the middle one EMPTY. An empty tx still occupies a
     * slot on the wire (`0a 00`), which is why the count matters. */
    {
        cmt_pb_data_t  d;
        cmt_pb_bytes_t slots[4];
        cmt_pb_bytes_t back_slots[4];
        cmt_pb_data_t  back;
        uint8_t        t0[3], t2[5];

        pat(t0, sizeof(t0), 0x90);
        pat(t2, sizeof(t2), 0x91);
        memset(&d, 0, sizeof(d));
        d.txs     = slots;
        d.txs_cap = 4;
        cmt_pb_data_init(&d);
        CHECK(cmt_pb_data_marshal(&d, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "data empty");
        CHECK(n == 0, "a Data with no txs encodes to NOTHING");

        slots[0].data = t0;   slots[0].len = sizeof(t0);
        slots[1].data = NULL; slots[1].len = 0;
        slots[2].data = t2;   slots[2].len = sizeof(t2);
        d.txs_len = 3;
        CHECK(cmt_pb_data_marshal(&d, g_buf, sizeof(g_buf), &n) == CMT_OK,
              "data 3");
        CHECK(is_vec("Data{3 txs}", g_buf, n, V_DATA_3TX, V_DATA_3TX_LEN),
              "an empty tx is still one repeated element");
        OK();

        memset(&back, 0, sizeof(back));
        back.txs     = back_slots;
        back.txs_cap = 4;
        arena_reset();
        CHECK(cmt_pb_data_unmarshal(g_buf, n, &back, &g_arena) == CMT_OK,
              "decode");
        CHECK(back.txs_len == 3, "three txs back, empty one included");
        CHECK(back.txs[1].len == 0, "the middle tx is empty");
        CHECK(back.txs[2].len == sizeof(t2), "order preserved");
        CHECK(cmt_pb_data_marshal(&back, g_buf2, sizeof(g_buf2), &n2)
              == CMT_OK, "re-marshal");
        CHECK(is_vec("Data round trip", g_buf2, n2, g_buf, n), "round trip");
        OK();

        /* DELTA 1 — empty txs at BOTH ENDS. The middle-empty case above
         * would still pass an encoder that dropped only a LEADING or only
         * a TRAILING empty element; this one cannot.
         * types.pb.go:1552-1560 writes all three. */
        {
            static const uint8_t ab[2] = { 0x61, 0x62 };

            slots[0].data = NULL; slots[0].len = 0;
            slots[1].data = ab;   slots[1].len = sizeof(ab);
            slots[2].data = NULL; slots[2].len = 0;
            d.txs_len = 3;
            CHECK(cmt_pb_data_marshal(&d, g_buf, sizeof(g_buf), &n)
                  == CMT_OK, "data empty ends");
            CHECK(is_vec("Data{\"\",\"ab\",\"\"}", g_buf, n,
                         V_DATA_EMPTY_ENDS, V_DATA_EMPTY_ENDS_LEN),
                  "a leading and a trailing empty tx are each one element");
            OK();

            memset(&back, 0, sizeof(back));
            back.txs     = back_slots;
            back.txs_cap = 4;
            arena_reset();
            CHECK(cmt_pb_data_unmarshal(g_buf, n, &back, &g_arena) == CMT_OK,
                  "decode");
            CHECK(back.txs_len == 3, "three txs back, both empties included");
            CHECK(back.txs[0].len == 0, "the first tx is empty");
            CHECK(back.txs[1].len == sizeof(ab), "the middle tx survives");
            CHECK(back.txs[2].len == 0, "the last tx is empty");
            CHECK(cmt_pb_data_marshal(&back, g_buf2, sizeof(g_buf2), &n2)
                  == CMT_OK, "re-marshal");
            CHECK(is_vec("Data empty-ends round trip", g_buf2, n2, g_buf, n),
                  "round trip");
            OK();

            /* Restore the 3-tx encoding the blocks below still use. */
            slots[0].data = t0;   slots[0].len = sizeof(t0);
            slots[1].data = NULL; slots[1].len = 0;
            slots[2].data = t2;   slots[2].len = sizeof(t2);
            d.txs_len = 3;
            CHECK(cmt_pb_data_marshal(&d, g_buf, sizeof(g_buf), &n)
                  == CMT_OK, "restore");
        }

        /* More txs than slots is REFUSED. */
        {
            cmt_pb_data_t  tight;
            cmt_pb_bytes_t two[2];

            memset(&tight, 0, sizeof(tight));
            tight.txs     = two;
            tight.txs_cap = 2;
            arena_reset();
            CHECK(cmt_pb_data_unmarshal(g_buf, n, &tight, &g_arena)
                  == CMT_REJECT, "three txs into two slots must REJECT");
            OK();
        }

        /* An arena too small for the payloads is REFUSED, not overrun. */
        {
            uint8_t         tiny_bytes[2];
            cmt_pb_arena_t  tiny;

            tiny.buf = tiny_bytes;
            tiny.cap = sizeof(tiny_bytes);
            tiny.used = 0;
            memset(&back, 0, sizeof(back));
            back.txs     = back_slots;
            back.txs_cap = 4;
            CHECK(cmt_pb_data_unmarshal(g_buf, n, &back, &tiny)
                  == CMT_REJECT, "a full arena must REJECT");
            OK();
        }
    }

    /* ExecTxResult — the four deterministic fields only. */
    {
        cmt_pb_exec_tx_result_t r;
        uint8_t                 data[5];

        cmt_pb_exec_tx_result_init(&r);
        CHECK(cmt_pb_exec_tx_result_marshal(&r, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "result zero");
        CHECK(n == 0,
              "a wholly zero ExecTxResult encodes to NOTHING — the empty "
              "LastResultsHash leaf");
        pat(data, sizeof(data), 0xC0);
        r.code = 7;
        r.data.data = data;
        r.data.len  = sizeof(data);
        r.gas_wanted = 1000;
        r.gas_used   = 999;
        CHECK(cmt_pb_exec_tx_result_marshal(&r, g_buf, sizeof(g_buf), &n)
              == CMT_OK, "result A");
        CHECK(is_vec("ExecTxResult", g_buf, n, V_EXECTXRESULT_A,
                     V_EXECTXRESULT_A_LEN),
              "code 1, data 2, gas_wanted 5, gas_used 6");
        arena_reset();
        CHECK(cmt_pb_exec_tx_result_unmarshal(g_buf, n, &r, &g_arena)
              == CMT_OK, "decode");
        CHECK(r.code == 7 && r.gas_wanted == 1000 && r.gas_used == 999,
              "round trip");
        OK();

        /* The stated deviation: a stripped field REFUSES. Field 3 is
         * `log`, which deterministicExecTxResult drops and this port never
         * writes, so a message carrying it is not ours. */
        {
            static const uint8_t with_log[5] = { 0x1a, 0x02, 'h', 'i', 0x00 };
            static const uint8_t with_events[3] = { 0x3a, 0x00, 0x00 };

            arena_reset();
            CHECK(cmt_pb_exec_tx_result_unmarshal(with_log, 4, &r, &g_arena)
                  == CMT_REJECT, "field 3 (log) must REJECT");
            CHECK(cmt_pb_exec_tx_result_unmarshal(with_events, 2, &r,
                                                  &g_arena) == CMT_REJECT,
                  "field 7 (events) must REJECT");
            OK();
        }
    }

    /* DuplicateVoteEvidence, and the Evidence oneof around it. The two are
     * DIFFERENT byte strings: Bytes()/Hash() marshal the BARE evidence
     * (evidence.go:95-108) while the block wire carries the wrapper. */
    {
        static cmt_pb_duplicate_vote_evidence_t dve;
        static cmt_pb_duplicate_vote_evidence_t back;
        static cmt_pb_evidence_t                ev;

        cmt_pb_duplicate_vote_evidence_init(&dve);
        CHECK(cmt_pb_duplicate_vote_evidence_marshal(&dve, g_buf,
                                                     sizeof(g_buf), &n)
              == CMT_OK, "dve zero");
        CHECK(is_vec("DuplicateVoteEvidence{zero}", g_buf, n, V_DVE_ZERO,
                     V_DVE_ZERO_LEN),
              "the votes are pointers and vanish; the timestamp does not");
        OK();

        dve.has_vote_a = true;
        cmt_pb_vote_init(&dve.vote_a);
        dve.vote_a.type = CMT_PB_MSG_TYPE_PRECOMMIT;
        dve.vote_a.height = 42;
        dve.vote_a.round = 1;
        memcpy(dve.vote_a.block_id.hash, HASH_B, 64);
        dve.vote_a.block_id.hash_len = 64;
        dve.vote_a.block_id.part_set_header.total = 7;
        memcpy(dve.vote_a.block_id.part_set_header.hash, HASH_A, 64);
        dve.vote_a.block_id.part_set_header.hash_len = 64;
        dve.vote_a.timestamp = TS_A;
        memcpy(dve.vote_a.validator_address, ADDR_A, 32);
        dve.vote_a.validator_address_len = 32;
        dve.vote_a.validator_index = 3;
        memcpy(dve.vote_a.signature, SIG_S, sizeof(SIG_S));
        dve.vote_a.signature_len = sizeof(SIG_S);

        dve.has_vote_b = true;
        dve.vote_b = dve.vote_a;
        memcpy(dve.vote_b.block_id.hash, HASH_C, 64);   /* the conflict */

        dve.total_voting_power = 150;
        dve.validator_power    = 100;
        dve.timestamp          = TS_A;

        CHECK(cmt_pb_duplicate_vote_evidence_marshal(&dve, g_buf,
                                                     sizeof(g_buf), &n)
              == CMT_OK, "dve A");
        CHECK(is_digest("DuplicateVoteEvidence (BARE — what Hash() uses)",
                        g_buf, n, V_DVE_A_LEN, V_DVE_A_SHA3), "dve");
        arena_reset();
        CHECK(cmt_pb_duplicate_vote_evidence_unmarshal(g_buf, n, &back,
                                                       &g_arena) == CMT_OK,
              "decode");
        CHECK(back.has_vote_a && back.has_vote_b, "both votes back");
        CHECK(back.total_voting_power == 150, "power back");
        CHECK(memcmp(back.vote_b.block_id.hash, HASH_C, 64) == 0,
              "the conflicting BlockID survived");
        CHECK(cmt_pb_duplicate_vote_evidence_marshal(&back, g_buf2,
                                                     sizeof(g_buf2), &n2)
              == CMT_OK, "re-marshal");
        CHECK(is_vec("dve round trip", g_buf2, n2, g_buf, n), "round trip");
        OK();

        cmt_pb_evidence_init(&ev);
        ev.has_duplicate_vote_evidence = true;
        ev.duplicate_vote_evidence = dve;
        CHECK(cmt_pb_evidence_marshal(&ev, g_buf2, sizeof(g_buf2), &n2)
              == CMT_OK, "evidence wrapper");
        CHECK(is_digest("Evidence{DuplicateVote}", g_buf2, n2,
                        V_EVIDENCE_DVE_A_LEN, V_EVIDENCE_DVE_A_SHA3),
              "Evidence");
        CHECK(n2 != n,
              "the wrapper and the bare evidence must be DIFFERENT bytes");
        OK();

        /* The light-client branch is out of scope and REFUSED, not
         * skipped — silently dropping an evidence item would let two
         * nodes hash the same list differently. */
        {
            static const uint8_t light[4] = { 0x12, 0x02, 0x08, 0x01 };

            arena_reset();
            CHECK(cmt_pb_evidence_unmarshal(light, sizeof(light), &ev,
                                            &g_arena) == CMT_REJECT,
                  "the LightClientAttackEvidence branch must REJECT");
            OK();
        }
    }
    return 0;
}

/* ══ BitArray codec ══════════════════════════════════════════════════ */

static int test_bit_array_codec(void)
{
    cmt_bit_array_t ba;
    size_t          n;
    int             i;

    /* ToProto returns the reference's nil for an empty array. */
    CHECK(cmt_bits_to_proto(NULL, g_buf, sizeof(g_buf), &n) == CMT_BITS_NIL,
          "nil ToProto");
    CHECK(n == 0, "and writes nothing");
    OK();

    CHECK(cmt_bits_new(&ba, 1) == CMT_OK, "new 1");
    CHECK(cmt_bits_set_index(&ba, 0, true) == 1, "set 0");
    CHECK(cmt_bits_to_proto(&ba, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "to_proto 1 bit");
    CHECK(is_vec("BitArray{1,[1]}", g_buf, n, V_BITARRAY_1BIT,
                 V_BITARRAY_1BIT_LEN), "BitArray{1 bit}");
    OK();

    /* bits = 140, elems = [1, all-ones, 0xFFF] — the PACKED form: ONE tag
     * 0x12, one total length, then the varints back to back (rule f). */
    CHECK(cmt_bits_new(&ba, 140) == CMT_OK, "new 140");
    CHECK(cmt_bits_set_index(&ba, 0, true) == 1, "bit 0");
    for (i = 64; i < 140; i++) {
        CHECK(cmt_bits_set_index(&ba, i, true) == 1, "bits 64..139");
    }
    CHECK(ba.elems[0] == 1u, "word 0");
    CHECK(ba.elems[1] == ~(uint64_t)0, "word 1 all ones");
    CHECK(ba.elems[2] == 0xFFFu, "word 2 is twelve bits");
    CHECK(cmt_bits_to_proto(&ba, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "to_proto 140");
    CHECK(is_vec("BitArray{140, 3 elems}", g_buf, n, V_BITARRAY_3ELEMS,
                 V_BITARRAY_3ELEMS_LEN), "the packed encoding");
    CHECK(g_buf[3] == 0x12, "one tag 0x12 for the whole elems list");
    CHECK(g_buf[4] == 0x0d, "one total length of thirteen bytes");
    OK();

    /* Round trip. */
    {
        cmt_bit_array_t back;

        CHECK(cmt_bits_from_proto(g_buf, n, &back) == CMT_OK, "from_proto");
        CHECK(back.bits == 140, "bits back");
        CHECK(back.n_elems == 3, "words back");
        CHECK(memcmp(back.elems, ba.elems, 3 * sizeof(uint64_t)) == 0,
              "contents back");
        OK();
    }

    /* The UNPACKED form is accepted too, exactly as the generated decoder
     * accepts wire type 0 for a repeated scalar. bits = 1, elems = [1]. */
    {
        static const uint8_t unpacked[4] = { 0x08, 0x01, 0x10, 0x01 };
        cmt_bit_array_t      back;

        CHECK(cmt_bits_from_proto(unpacked, sizeof(unpacked), &back)
              == CMT_OK, "the unpacked form must be accepted");
        CHECK(back.bits == 1 && back.n_elems == 1 && back.elems[0] == 1,
              "unpacked contents");
        OK();
    }

    /* The refusal the REFERENCE DOES NOT MAKE (bit_array.go:493-496):
     * elems must be exactly (bits+63)/64. Without it, a later index
     * derived from bits reads out of bounds in C. */
    {
        cmt_bit_array_t back;
        /* bits = 140 but only ONE elem */
        static const uint8_t too_few[6] = {
            0x08, 0x8c, 0x01, 0x12, 0x01, 0x01
        };
        /* bits = 1 but TWO elems */
        static const uint8_t too_many[6] = {
            0x08, 0x01, 0x12, 0x02, 0x01, 0x02
        };
        /* bits = 140 and no elems at all */
        static const uint8_t none[3] = { 0x08, 0x8c, 0x01 };
        /* bits = -1 (ten-byte negative varint), one elem */
        static const uint8_t negative[15] = {
            0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x01, 0x12, 0x01, 0x01
        };

        CHECK(cmt_bits_from_proto(too_few, sizeof(too_few), &back)
              == CMT_REJECT, "too few elems must REJECT");
        CHECK(cmt_bits_from_proto(too_many, sizeof(too_many), &back)
              == CMT_REJECT, "too many elems must REJECT");
        CHECK(cmt_bits_from_proto(none, sizeof(none), &back) == CMT_REJECT,
              "bits with no elems must REJECT");
        CHECK(cmt_bits_from_proto(negative, 14, &back) == CMT_REJECT,
              "a negative bits count must REJECT");
        OK();
    }

    /* Past the derived capacity: bits = 100000 would need 1563 words. */
    {
        cmt_bit_array_t back;
        uint8_t         b[8];
        size_t          off = 0;

        b[off++] = 0x08;
        CHECK(cmt_pb_put_uvarint(b, sizeof(b), &off, 100000) == CMT_OK, "l");
        CHECK(cmt_bits_from_proto(b, off, &back) == CMT_REJECT,
              "a bits count past the derived bound must REJECT");
        OK();
    }
    return 0;
}

/* ══ truncation and over-read ════════════════════════════════════════ */

/* Every prefix of a valid encoding must either decode cleanly or be
 * REFUSED — never read past the buffer. The buffer is an EXACT-SIZE heap
 * allocation so a sanitizer can see an over-read. */
static int truncation_sweep(const char *what, const uint8_t *full,
                            size_t full_len,
                            int (*fn)(const uint8_t *, size_t, void *),
                            void *m)
{
    size_t k;

    for (k = 0; k < full_len; k++) {
        uint8_t *b = (uint8_t *)malloc(k == 0 ? 1 : k);
        int      rc;

        if (b == NULL) {
            fprintf(stderr, "%s: malloc failed\n", what);
            return 0;
        }
        if (k != 0) {
            memcpy(b, full, k);
        }
        rc = fn(b, k, m);
        free(b);
        if (rc != CMT_OK && rc != CMT_REJECT) {
            fprintf(stderr, "%s: prefix %zu gave %d\n", what, k, rc);
            return 0;
        }
    }
    return 1;
}

static int wrap_header(const uint8_t *in, size_t len, void *m)
{
    return cmt_pb_header_unmarshal(in, len, (cmt_pb_header_t *)m);
}

static int wrap_commit_sig(const uint8_t *in, size_t len, void *m)
{
    return cmt_pb_commit_sig_unmarshal(in, len, (cmt_pb_commit_sig_t *)m);
}

static int wrap_canonical_vote(const uint8_t *in, size_t len, void *m)
{
    return cmt_pb_canonical_vote_unmarshal(in, len,
                                           (cmt_pb_canonical_vote_t *)m);
}

static int wrap_block_id(const uint8_t *in, size_t len, void *m)
{
    return cmt_pb_block_id_unmarshal(in, len, (cmt_pb_block_id_t *)m);
}

static int test_truncation(void)
{
    static cmt_pb_header_t         h;
    cmt_pb_commit_sig_t            cs;
    cmt_pb_canonical_vote_t        cv;
    cmt_pb_block_id_t              b;
    size_t                         n;

    CHECK(truncation_sweep("CommitSig", V_COMMITSIG_ABSENT,
                           V_COMMITSIG_ABSENT_LEN, wrap_commit_sig, &cs),
          "CommitSig truncation");
    CHECK(truncation_sweep("CanonicalVote", V_CANONVOTE_GOLDEN,
                           V_CANONVOTE_GOLDEN_LEN, wrap_canonical_vote, &cv),
          "CanonicalVote truncation");
    CHECK(truncation_sweep("BlockID", V_BLOCKID_ZERO, V_BLOCKID_ZERO_LEN,
                           wrap_block_id, &b), "BlockID truncation");
    CHECK(truncation_sweep("Header", V_HEADER_ZERO, V_HEADER_ZERO_LEN,
                           wrap_header, &h), "Header truncation");
    OK();

    /* The full Header too — 756 bytes of prefixes. */
    cmt_pb_header_init(&h);
    h.version.block = 11;
    h.height = 42;
    h.time = TS_A;
    memcpy(h.chain_id, CHAIN, 32);   h.chain_id_len = 32;
    memcpy(h.app_hash, HASH_A, 64);  h.app_hash_len = 64;
    CHECK(cmt_pb_header_marshal(&h, g_buf, sizeof(g_buf), &n) == CMT_OK,
          "header");
    CHECK(truncation_sweep("Header (populated)", g_buf, n, wrap_header, &h),
          "populated Header truncation");
    OK();

    /* A length field that claims more than the buffer holds. */
    {
        static const uint8_t lying_len[3] = { 0x0a, 0x40, 0x00 };

        CHECK(cmt_pb_block_id_unmarshal(lying_len, 3, &b) == CMT_REJECT,
              "a length past the end of the buffer must REJECT");
        OK();
    }

    /* A group start with no end (wire type 3) inside an unknown field. */
    {
        static const uint8_t open_group[2] = { 0xfb, 0x01 };

        CHECK(cmt_pb_block_id_unmarshal(open_group, 2, &b) == CMT_REJECT,
              "an unterminated group must REJECT");
        OK();
    }

    /* A bare end-group marker (wire type 4) is refused by the tag loop. */
    {
        static const uint8_t end_group[1] = { 0x0c };

        CHECK(cmt_pb_block_id_unmarshal(end_group, 1, &b) == CMT_REJECT,
              "a bare end-group marker must REJECT");
        OK();
    }

    /* Field number 0 is an illegal tag. */
    {
        static const uint8_t field_zero[2] = { 0x00, 0x00 };

        CHECK(cmt_pb_block_id_unmarshal(field_zero, 2, &b) == CMT_REJECT,
              "field number 0 must REJECT");
        OK();
    }

    /* An output buffer too small for the encoding REJECTs rather than
     * writing past it. */
    {
        CHECK(cmt_pb_header_marshal(&h, g_buf, 4, &n) == CMT_REJECT,
              "a short output buffer must REJECT");
        CHECK(cmt_pb_block_id_marshal(&b, g_buf, 1, &n) == CMT_REJECT,
              "a one-byte output buffer must REJECT");
        CHECK(cmt_pb_block_id_marshal(&b, g_buf, 0, &n) == CMT_REJECT,
              "a zero-byte output buffer must REJECT");
        OK();
    }
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * WAVE R1-B ADDITION — types.ExtendedCommitSig and types.ExtendedCommit,
 * the two messages of types.proto that wave R1-A did not carry.
 *
 * Vectors from shared/dnac/tests/cmt_pb_oracle.py's emit_extended(),
 * which was appended to the same independent oracle. Nothing above this
 * banner changed.
 * ══════════════════════════════════════════════════════════════════════ */

/* An ABSENT ExtendedCommitSig is the SAME fifteen bytes as an Absent
 * CommitSig: the extension fields are empty and omitted, and the
 * ALWAYS-emitted timestamp carries Go's zero time. */
#define V_ECS_ABSENT_LEN 15
static const uint8_t V_ECS_ABSENT[15] = {
    0x08, 0x01, 0x1a, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe, 0xff,
    0xff, 0xff, 0x01,
};
#define V_ECS_NIL_LEN 32
static const uint8_t V_ECS_NIL[32] = {
    0x08, 0x03, 0x12, 0x04, 0x40, 0x47, 0x4e, 0x55, 0x1a, 0x0b, 0x08, 0x80,
    0xe2, 0xcf, 0xaa, 0x06, 0x10, 0x95, 0x9a, 0xef, 0x3a, 0x22, 0x09, 0x60,
    0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a, 0x91, 0x98,
};
#define V_ECS_EXT_LEN 48
static const uint8_t V_ECS_EXT[48] = {
    0x08, 0x02, 0x12, 0x04, 0x40, 0x47, 0x4e, 0x55, 0x1a, 0x0b, 0x08, 0x80,
    0xe2, 0xcf, 0xaa, 0x06, 0x10, 0x95, 0x9a, 0xef, 0x3a, 0x22, 0x09, 0x60,
    0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a, 0x91, 0x98, 0x2a, 0x03, 0x65, 0x78,
    0x74, 0x32, 0x09, 0x60, 0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a, 0x91, 0x98,
};
/* An EMPTY extension with a PRESENT extension signature: field 5 is
 * omitted (rule (a) for a singular bytes field) while field 6 is written. */
#define V_ECS_EMPTY_EXT_LEN 43
static const uint8_t V_ECS_EMPTY_EXT[43] = {
    0x08, 0x02, 0x12, 0x04, 0x40, 0x47, 0x4e, 0x55, 0x1a, 0x0b, 0x08, 0x80,
    0xe2, 0xcf, 0xaa, 0x06, 0x10, 0x95, 0x9a, 0xef, 0x3a, 0x22, 0x09, 0x60,
    0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a, 0x91, 0x98, 0x32, 0x09, 0x60, 0x67,
    0x6e, 0x75, 0x7c, 0x83, 0x8a, 0x91, 0x98,
};
#define V_ECS_FULL_LEN 9314
static const char V_ECS_FULL_SHA3[] =
    "6ee89abf8819b0bfa5fedfd760c9ac382712f4f4681ac69f514dab957510e14e"
    "33d6960dc2c2341e73947be35aa5843449918f85cf39980401abdd27df6c414d";
/* An ExtendedCommit with zero height and round and NO entries: only the
 * ALWAYS-emitted empty block_id survives, as `1a 02 12 00`. */
#define V_EC_EMPTY_LEN 4
static const uint8_t V_EC_EMPTY[4] = { 0x1a, 0x02, 0x12, 0x00 };
#define V_EC_THREE_LEN 244
static const uint8_t V_EC_THREE[244] = {
    0x08, 0x09, 0x10, 0x02, 0x1a, 0x88, 0x01, 0x0a, 0x40, 0x20, 0x27, 0x2e,
    0x35, 0x3c, 0x43, 0x4a, 0x51, 0x58, 0x5f, 0x66, 0x6d, 0x74, 0x7b, 0x82,
    0x89, 0x90, 0x97, 0x9e, 0xa5, 0xac, 0xb3, 0xba, 0xc1, 0xc8, 0xcf, 0xd6,
    0xdd, 0xe4, 0xeb, 0xf2, 0xf9, 0x00, 0x07, 0x0e, 0x15, 0x1c, 0x23, 0x2a,
    0x31, 0x38, 0x3f, 0x46, 0x4d, 0x54, 0x5b, 0x62, 0x69, 0x70, 0x77, 0x7e,
    0x85, 0x8c, 0x93, 0x9a, 0xa1, 0xa8, 0xaf, 0xb6, 0xbd, 0xc4, 0xcb, 0xd2,
    0xd9, 0x12, 0x44, 0x08, 0x07, 0x12, 0x40, 0x10, 0x17, 0x1e, 0x25, 0x2c,
    0x33, 0x3a, 0x41, 0x48, 0x4f, 0x56, 0x5d, 0x64, 0x6b, 0x72, 0x79, 0x80,
    0x87, 0x8e, 0x95, 0x9c, 0xa3, 0xaa, 0xb1, 0xb8, 0xbf, 0xc6, 0xcd, 0xd4,
    0xdb, 0xe2, 0xe9, 0xf0, 0xf7, 0xfe, 0x05, 0x0c, 0x13, 0x1a, 0x21, 0x28,
    0x2f, 0x36, 0x3d, 0x44, 0x4b, 0x52, 0x59, 0x60, 0x67, 0x6e, 0x75, 0x7c,
    0x83, 0x8a, 0x91, 0x98, 0x9f, 0xa6, 0xad, 0xb4, 0xbb, 0xc2, 0xc9, 0x22,
    0x0f, 0x08, 0x01, 0x1a, 0x0b, 0x08, 0x80, 0x92, 0xb8, 0xc3, 0x98, 0xfe,
    0xff, 0xff, 0xff, 0x01, 0x22, 0x30, 0x08, 0x02, 0x12, 0x04, 0x40, 0x47,
    0x4e, 0x55, 0x1a, 0x0b, 0x08, 0x80, 0xe2, 0xcf, 0xaa, 0x06, 0x10, 0x95,
    0x9a, 0xef, 0x3a, 0x22, 0x09, 0x60, 0x67, 0x6e, 0x75, 0x7c, 0x83, 0x8a,
    0x91, 0x98, 0x2a, 0x03, 0x65, 0x78, 0x74, 0x32, 0x09, 0x60, 0x67, 0x6e,
    0x75, 0x7c, 0x83, 0x8a, 0x91, 0x98, 0x22, 0x20, 0x08, 0x03, 0x12, 0x04,
    0x40, 0x47, 0x4e, 0x55, 0x1a, 0x0b, 0x08, 0x80, 0xe2, 0xcf, 0xaa, 0x06,
    0x10, 0x95, 0x9a, 0xef, 0x3a, 0x22, 0x09, 0x60, 0x67, 0x6e, 0x75, 0x7c,
    0x83, 0x8a, 0x91, 0x98,
};

static int test_extended_commit(void)
{
    static cmt_pb_extended_commit_sig_t ecs;
    static cmt_pb_extended_commit_sig_t back;
    static cmt_pb_extended_commit_sig_t slots[3];
    cmt_pb_extended_commit_t            ec;
    cmt_pb_extended_commit_t            ec_back;
    size_t                              n;

    /* ── ExtendedCommitSig ─────────────────────────────────────────── */

    /* ABSENT: everything empty, Go's zero time, fifteen bytes. */
    cmt_pb_extended_commit_sig_init(&ecs);
    ecs.commit_sig.block_id_flag = (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT;
    CHECK(cmt_pb_extended_commit_sig_marshal(&ecs, g_buf, sizeof(g_buf),
                                             &n) == CMT_OK,
          "marshal an Absent ExtendedCommitSig");
    CHECK(is_vec("ExtendedCommitSig{Absent}", g_buf, n, V_ECS_ABSENT,
                 V_ECS_ABSENT_LEN),
          "an Absent extended entry is the Absent CommitSig, unchanged");
    OK();

    /* NIL with a short address, a real timestamp and a short signature. */
    cmt_pb_extended_commit_sig_init(&ecs);
    ecs.commit_sig.block_id_flag = (int32_t)CMT_PB_BLOCK_ID_FLAG_NIL;
    memcpy(ecs.commit_sig.validator_address, ADDR_A, 4);
    ecs.commit_sig.validator_address_len = 4;
    ecs.commit_sig.timestamp = TS_A;
    memcpy(ecs.commit_sig.signature, SIG_S, sizeof(SIG_S));
    ecs.commit_sig.signature_len = sizeof(SIG_S);
    CHECK(cmt_pb_extended_commit_sig_marshal(&ecs, g_buf, sizeof(g_buf),
                                             &n) == CMT_OK, "marshal Nil");
    CHECK(is_vec("ExtendedCommitSig{Nil}", g_buf, n, V_ECS_NIL,
                 V_ECS_NIL_LEN),
          "fields 5 and 6 are omitted when empty");
    OK();

    /* COMMIT with an extension and its signature. */
    ecs.commit_sig.block_id_flag = (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT;
    ecs.extension.data = (const uint8_t *)"ext";
    ecs.extension.len  = 3;
    memcpy(ecs.extension_signature, SIG_S, sizeof(SIG_S));
    ecs.extension_signature_len = sizeof(SIG_S);
    CHECK(cmt_pb_extended_commit_sig_marshal(&ecs, g_buf, sizeof(g_buf),
                                             &n) == CMT_OK, "marshal Ext");
    CHECK(is_vec("ExtendedCommitSig{ext}", g_buf, n, V_ECS_EXT,
                 V_ECS_EXT_LEN),
          "fields 5 and 6 follow the four CommitSig fields");
    OK();

    /* Round trip through the decoder, and the arena contract: the decoded
     * extension must NOT point into the input buffer. */
    arena_reset();
    CHECK(cmt_pb_extended_commit_sig_unmarshal(g_buf, n, &back,
                                               &g_arena) == CMT_OK,
          "decode it back");
    CHECK(back.commit_sig.block_id_flag ==
          (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT &&
          back.commit_sig.validator_address_len == 4 &&
          back.commit_sig.timestamp.seconds == TS_A.seconds &&
          back.commit_sig.timestamp.nanos == TS_A.nanos &&
          back.commit_sig.signature_len == sizeof(SIG_S) &&
          back.extension.len == 3 &&
          back.extension_signature_len == sizeof(SIG_S),
          "every field came back");
    CHECK(back.extension.data >= g_arena_bytes &&
          back.extension.data < g_arena_bytes + sizeof(g_arena_bytes),
          "the extension lives in the ARENA, not in the input buffer");
    CHECK(memcmp(back.extension.data, "ext", 3) == 0, "and it is `ext`");
    OK();

    /* An EMPTY extension with a present extension signature: 5 omitted,
     * 6 written. */
    ecs.extension.data = NULL;
    ecs.extension.len  = 0;
    CHECK(cmt_pb_extended_commit_sig_marshal(&ecs, g_buf, sizeof(g_buf),
                                             &n) == CMT_OK,
          "marshal an empty extension");
    CHECK(is_vec("ExtendedCommitSig{empty ext}", g_buf, n, V_ECS_EMPTY_EXT,
                 V_ECS_EMPTY_EXT_LEN),
          "an empty extension is OMITTED while its signature is written");
    OK();

    /* Full-size fields: 32-byte address, 4627-byte signature and
     * extension signature. */
    cmt_pb_extended_commit_sig_init(&ecs);
    ecs.commit_sig.block_id_flag = (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT;
    memcpy(ecs.commit_sig.validator_address, ADDR_A, sizeof(ADDR_A));
    ecs.commit_sig.validator_address_len = sizeof(ADDR_A);
    ecs.commit_sig.timestamp = TS_A;
    memcpy(ecs.commit_sig.signature, SIG_FULL, sizeof(SIG_FULL));
    ecs.commit_sig.signature_len = sizeof(SIG_FULL);
    ecs.extension.data = (const uint8_t *)"ext";
    ecs.extension.len  = 3;
    memcpy(ecs.extension_signature, SIG_FULL, sizeof(SIG_FULL));
    ecs.extension_signature_len = sizeof(SIG_FULL);
    CHECK(cmt_pb_extended_commit_sig_marshal(&ecs, g_buf, sizeof(g_buf),
                                             &n) == CMT_OK,
          "marshal a full-size extended entry");
    CHECK(is_digest("ExtendedCommitSig{full}", g_buf, n, V_ECS_FULL_LEN,
                    V_ECS_FULL_SHA3),
          "the full-size encoding is the oracle's");
    OK();

    /* An over-long field REFUSES rather than writing past the struct. */
    ecs.extension_signature_len = (size_t)CMT_PB_SIG_MAX + 1u;
    CHECK(cmt_pb_extended_commit_sig_marshal(&ecs, g_buf, sizeof(g_buf),
                                             &n) == CMT_REJECT,
          "an over-long extension signature is refused");
    ecs.extension_signature_len = sizeof(SIG_FULL);
    CHECK(cmt_pb_extended_commit_sig_marshal(&ecs, g_buf, 8, &n)
          == CMT_REJECT, "a buffer that cannot hold it is refused");
    OK();

    /* ── ExtendedCommit ────────────────────────────────────────────── */

    /* Zero height and round, no entries: only the ALWAYS-emitted
     * block_id survives, and an empty BlockID is `12 00` inside it. */
    memset(&ec, 0, sizeof(ec));
    cmt_pb_extended_commit_init(&ec);
    CHECK(cmt_pb_extended_commit_marshal(&ec, g_buf, sizeof(g_buf), &n)
          == CMT_OK, "marshal an empty ExtendedCommit");
    CHECK(is_vec("ExtendedCommit{empty}", g_buf, n, V_EC_EMPTY,
                 V_EC_EMPTY_LEN),
          "the ALWAYS-emitted block_id is 1a 02 12 00, not an omission");
    OK();

    /* Three entries — Absent, Commit-with-extension, Nil. */
    cmt_pb_extended_commit_sig_init(&slots[0]);
    slots[0].commit_sig.block_id_flag =
        (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT;
    cmt_pb_extended_commit_sig_init(&slots[1]);
    slots[1].commit_sig.block_id_flag =
        (int32_t)CMT_PB_BLOCK_ID_FLAG_COMMIT;
    memcpy(slots[1].commit_sig.validator_address, ADDR_A, 4);
    slots[1].commit_sig.validator_address_len = 4;
    slots[1].commit_sig.timestamp = TS_A;
    memcpy(slots[1].commit_sig.signature, SIG_S, sizeof(SIG_S));
    slots[1].commit_sig.signature_len = sizeof(SIG_S);
    slots[1].extension.data = (const uint8_t *)"ext";
    slots[1].extension.len  = 3;
    memcpy(slots[1].extension_signature, SIG_S, sizeof(SIG_S));
    slots[1].extension_signature_len = sizeof(SIG_S);
    cmt_pb_extended_commit_sig_init(&slots[2]);
    slots[2].commit_sig.block_id_flag = (int32_t)CMT_PB_BLOCK_ID_FLAG_NIL;
    memcpy(slots[2].commit_sig.validator_address, ADDR_A, 4);
    slots[2].commit_sig.validator_address_len = 4;
    slots[2].commit_sig.timestamp = TS_A;
    memcpy(slots[2].commit_sig.signature, SIG_S, sizeof(SIG_S));
    slots[2].commit_sig.signature_len = sizeof(SIG_S);

    memset(&ec, 0, sizeof(ec));
    cmt_pb_extended_commit_init(&ec);
    ec.height   = 9;
    ec.round    = 2;
    memcpy(ec.block_id.hash, HASH_B, sizeof(HASH_B));
    ec.block_id.hash_len = sizeof(HASH_B);
    ec.block_id.part_set_header.total = 7;
    memcpy(ec.block_id.part_set_header.hash, HASH_A, sizeof(HASH_A));
    ec.block_id.part_set_header.hash_len = sizeof(HASH_A);
    ec.extended_signatures     = slots;
    ec.extended_signatures_cap = 3;
    ec.extended_signatures_len = 3;
    CHECK(cmt_pb_extended_commit_marshal(&ec, g_buf, sizeof(g_buf), &n)
          == CMT_OK, "marshal three entries");
    CHECK(is_vec("ExtendedCommit{three}", g_buf, n, V_EC_THREE,
                 V_EC_THREE_LEN),
          "three entries encode to the oracle's bytes, in list order");
    OK();

    /* Round trip, with caller-owned storage that is EXACTLY big enough. */
    {
        static cmt_pb_extended_commit_sig_t back_slots[3];

        arena_reset();
        memset(&ec_back, 0, sizeof(ec_back));
        ec_back.extended_signatures     = back_slots;
        ec_back.extended_signatures_cap = 3;
        CHECK(cmt_pb_extended_commit_unmarshal(g_buf, n, &ec_back,
                                               &g_arena) == CMT_OK,
              "decode three entries");
        CHECK(ec_back.height == 9 && ec_back.round == 2 &&
              ec_back.extended_signatures_len == 3 &&
              ec_back.block_id.hash_len == 64 &&
              ec_back.block_id.part_set_header.total == 7,
              "the header fields came back");
        CHECK(back_slots[0].commit_sig.block_id_flag ==
              (int32_t)CMT_PB_BLOCK_ID_FLAG_ABSENT &&
              back_slots[1].extension.len == 3 &&
              back_slots[2].commit_sig.block_id_flag ==
              (int32_t)CMT_PB_BLOCK_ID_FLAG_NIL,
              "and so did every entry, in order");
        OK();

        /* INVARIANT 7495d337: one slot too few REFUSES rather than
         * writing past the caller's array. */
        arena_reset();
        memset(&ec_back, 0, sizeof(ec_back));
        ec_back.extended_signatures     = back_slots;
        ec_back.extended_signatures_cap = 2;
        CHECK(cmt_pb_extended_commit_unmarshal(g_buf, n, &ec_back,
                                               &g_arena) == CMT_REJECT,
              "too little entry storage is REFUSED, not overrun");
        /* And no storage at all. */
        memset(&ec_back, 0, sizeof(ec_back));
        CHECK(cmt_pb_extended_commit_unmarshal(g_buf, n, &ec_back,
                                               &g_arena) == CMT_REJECT,
              "a decode with no entry storage is refused");
        OK();

        /* Truncation. Field 4's elements are last in the encoding, so the
         * final byte of the message is inside the THIRD entry's own
         * length-delimited chunk: dropping it leaves that chunk's declared
         * length longer than what remains, and the decode must REFUSE.
         * Every prefix is copied into an EXACT-SIZE heap buffer, as the
         * prefix sweep above does, so a one-byte over-read is a heap
         * over-read that a sanitiser can see. */
        {
            size_t   k;
            size_t   bad_k     = 0;
            int      claimed_3 = 0;
            int      short_rc  = CMT_OK;
            uint8_t *b;

            b = (uint8_t *)malloc(n - 1u);
            CHECK(b != NULL, "malloc for the short buffer"); OK();
            memcpy(b, g_buf, n - 1u);
            arena_reset();
            memset(&ec_back, 0, sizeof(ec_back));
            ec_back.extended_signatures     = back_slots;
            ec_back.extended_signatures_cap = 3;
            short_rc = cmt_pb_extended_commit_unmarshal(b, n - 1u, &ec_back,
                                                        &g_arena);
            free(b);
            CHECK(short_rc == CMT_REJECT,
                  "one byte short of the whole message is REFUSED — the"
                  " last entry's declared length outruns the buffer");
            OK();

            /* And across every prefix: a shorter prefix may be a
             * well-formed SHORTER message (legal proto3), but it can never
             * yield all three entries, because the third entry's chunk
             * only completes at byte n. */
            for (k = 1; k < n; k++) {
                int rc_k;

                b = (uint8_t *)malloc(k);
                CHECK(b != NULL, "malloc for a prefix buffer");
                memcpy(b, g_buf, k);
                arena_reset();
                memset(&ec_back, 0, sizeof(ec_back));
                ec_back.extended_signatures     = back_slots;
                ec_back.extended_signatures_cap = 3;
                rc_k = cmt_pb_extended_commit_unmarshal(b, k, &ec_back,
                                                        &g_arena);
                free(b);
                if (rc_k != CMT_OK && rc_k != CMT_REJECT) {
                    claimed_3 = 1;              /* a FAULT is a defect too */
                    bad_k     = k;
                    break;
                }
                if (rc_k == CMT_OK &&
                    ec_back.extended_signatures_len == 3u) {
                    claimed_3 = 1;
                    bad_k     = k;
                    break;
                }
            }
            if (claimed_3) {
                fprintf(stderr,
                        "  first offending prefix length: %zu of %zu\n",
                        bad_k, n);
            }
            CHECK(!claimed_3,
                  "no prefix decodes into all three entries, and none"
                  " faults");
            OK();
        }
    }
    return 0;
}

int main(void)
{
    build_fixtures();
    arena_reset();

    if (test_primitives() != 0)            { return 1; }
    if (test_timestamp() != 0)             { return 1; }
    if (test_cdc_encode() != 0)            { return 1; }
    if (test_simple_messages() != 0)       { return 1; }
    if (test_public_key() != 0)            { return 1; }
    if (test_validators() != 0)            { return 1; }
    if (test_header() != 0)                { return 1; }
    if (test_vote_commit_proposal() != 0)  { return 1; }
    if (test_canonical() != 0)             { return 1; }
    if (test_proof_and_part() != 0)        { return 1; }
    if (test_data_results_evidence() != 0) { return 1; }
    if (test_bit_array_codec() != 0)       { return 1; }
    if (test_truncation() != 0)            { return 1; }
    if (test_extended_commit() != 0)       { return 1; }   /* wave R1-B */

    printf("test_cmt_pb: OK (%d groups)\n", g_checks);
    return 0;
}
