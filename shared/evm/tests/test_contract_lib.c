/**
 * @file test_contract_lib.c
 * @brief The Nodus contract library v0.2 (nodus/tools/evm/contracts) runs as
 *        designed in the engine's 32-byte mode: the v0.1 security contracts
 *        and the ML-DSA-87 companion library (MLDSA87, MLDSA87Attested).
 *
 * Governing records: docs/plans/2026-10-21-nodus-contract-library-design.md
 * rev 3 (§1 contract table, §5 test plan), docs/plans/decisions/
 * 2026-10-21-kurultay-30-summary.md, 2026-10-04-nodus-evm-domain.md decision
 * 3 (32-byte addresses), 2026-10-06-evm-dev-tooling.md item 1 (developer
 * pack), and the semantic rules of nodus/tools/evm/solc/README.md. For the
 * companion library: docs/plans/2026-10-22-mldsa87-companion-library-design.md
 * rev 2 (§1.2-1.5, §1.7, §5), docs/plans/decisions/2026-10-21-mldsa87-evm-
 * precompile.md (items 2, 3, 7(a), 8, TAG_ATTEST_V1, "Companion library: the
 * actionType") and 2026-10-22-kurultay-40-mldsa-companion-library-summary.md.
 *
 * WHAT IT PROVES
 *   For both committed compiler configurations (default = no optimizer, and
 *   --optimize; both --evm-version prague), every library contract and test
 *   mock deployed from its committed creation bytecode, with EOAs whose HIGH
 *   12 bytes are non-zero and their TWINS (same low 20 bytes, different high
 *   12 bytes):
 *   - Ownable (MockOwnable): first owner non-zero; onlyOwner; two-step
 *     transfer (nominate / accept); refused: transfer by a non-owner, to
 *     zero, accept by a non-nominee, by the nominee's twin, by a stale
 *     nominee after a second nomination; the events' address topics and raw
 *     slot 0 hold the full 32 bytes.
 *   - AccessControl (MockAccessControl): grant / revoke only by the role's
 *     admin; renounce only for yourself; role-admin isolation (ROLE_B's
 *     admin is ADMIN_B, not DEFAULT_ADMIN_ROLE); a repeated grant is a no-op
 *     without a log; RoleGranted / RoleRevoked topics; the raw hasRole slot
 *     keccak256(account32 ‖ keccak256(role ‖ 0)); the twin is never a holder.
 *   - ReentrancyGuard + Pausable (MockGuarded, MockActor): re-entry into the
 *     same and into another nonReentrant function is refused with
 *     ReentrantCall (the attacker records it); the guard works again after a
 *     revert; pause twice / unpause when not paused revert; a paused
 *     whenNotPaused function reverts while unmarked functions keep working;
 *     a whenPaused function (MockGuarded.pausedPing) reverts ExpectedPause()
 *     before the pause and after the unpause and runs while paused.
 *   - Timelock: constructor refusals (no proposer, no executor, zero
 *     account, the timelock's own address, minDelay above MAX_DELAY); the
 *     timelock alone holds DEFAULT_ADMIN_ROLE; schedule (PROPOSER only,
 *     minDelay <= delay <= MAX_DELAY, an id never scheduled twice in any
 *     state); execute (EXECUTOR only, at ready and not at ready - 1, once,
 *     never after cancel, a failed call leaves the op Pending and retryable,
 *     value from the timelock's balance); cancel (CANCELLER only,
 *     terminal); updateDelay only through a delayed self-call and never
 *     above MAX_DELAY; a role change through a delayed self-call, after
 *     which the former proposer can neither schedule nor grant directly;
 *     renounceRole reverts for every role; delayed self-calls that grant
 *     DEFAULT_ADMIN_ROLE to an account, renounce or revoke the timelock's
 *     own DEFAULT_ADMIN_ROLE, grant a role to address(0) or to the timelock,
 *     or revoke the last executor / last proposer all fail, with the inner
 *     error checked inside TimelockCallFailed(id, reason); the operation id
 *     equals keccak256(abi.encode(target, value, data, salt)) computed here.
 *   - MultisigVault: constructor refusals (zero / duplicate / self owner,
 *     threshold 0 or > count, 33 owners) and 32 owners accepted, addOwner
 *     at 32 owners fails; submit / approve / revoke / execute rules
 *     (non-owner, twin, double approval, below threshold, double execute,
 *     unknown id, revoke then execute below threshold, failed call
 *     retryable); addOwner / removeOwner / changeThreshold refused when
 *     called directly and working as passed proposals; every config change
 *     voids older proposals (remove -> re-add does not revive approvals); a
 *     change that breaks 1 <= threshold <= count, or adds the vault itself,
 *     fails. Every failed vault / timelock execute is checked byte for byte,
 *     including the target's revert data carried as `reason` (empty for a
 *     refused ticket call, which halts without data).
 *   - MilestoneEscrow: constructor refusals (zero / equal parties incl.
 *     arbiter == payer, the escrow's own address as any party, 0 or 33
 *     milestones, zero or non-q amount, deadline not in the future, a sum
 *     that overflows -> Panic(0x11)); fund (payer only, exact sum, once,
 *     refused at the deadline); every settlement refused before funding;
 *     release / resolve / refund of an invalid index refused;
 *     release / resolve / refund rules incl. refund at deadline - 1 and at
 *     the deadline; for each of the four first settlements, all four
 *     second settlements of that milestone revert; release / resolve still
 *     work after the deadline; withdraw (zero credit, twice, a reverting
 *     payee keeps its credit, a re-entering payee is paid once and its
 *     re-entry refused); value forced in by SELFDESTRUCT is never credited;
 *     a plain value send is refused; the accounting invariant
 *     unsettled + credited + withdrawn == funded; raw credit slots.
 *   - Ticket exit: a vault and a timelock execute to the ticket address with
 *     a 64-byte fingerprint and a q-multiple value creates exactly that
 *     ticket and the contract's balance drops by it; 63 bytes of calldata or
 *     a non-q value makes execute revert with no ticket and no balance
 *     change; `transfer()` to the ticket address and a 64-byte call with
 *     only the 2 300 stipend both revert, while the same mock forwarding all
 *     gas creates the ticket.
 *   - CALL-success semantics: a vault and a timelock execute whose target
 *     returns encoded `false` without reverting completes (Done / executed).
 *   - Deployed code of every contract and mock = the committed runtime.hex.
 *   - ML-DSA-87 companion library (MockAttested over MLDSA87 +
 *     MLDSA87Attested), in a SECOND engine state per configuration with
 *     mldsa_precompile = 1 (the cases above stay at 0). Signatures are made
 *     here with qgp_dsa87_sign_ctx under "nodus.evm.attest.v1" from four keys
 *     derived from fixed seeds; the signer's account is SHA3-512(pk)[0..32].
 *     Proven: a valid attestation applies its action once and emits
 *     AttestationConsumed; the same nonce is refused (same signature, and a
 *     second valid signature over the same nonce); a changed parameter, a
 *     changed nonce, another contract, another chain id, another actionType
 *     with the same parameter layout, a wrong signer, a flipped signature
 *     byte, an all-zero signature of the right size and a signature under the
 *     EMPTY context are each refused with MLDSA87InvalidSignature(signer); a
 *     wrong pk / sig length reverts MLDSA87BadLength, a 65 537-byte message
 *     reverts MLDSA87MessageTooLong before the call, a 65 536-byte message
 *     verifies; a zero expected signer reverts MLDSA87ZeroSigner; accepted at
 *     block.timestamp == expiry, AttestationExpired one second later; the
 *     misordered-header action reverts AttestationHeaderMismatch even with a
 *     valid signature over the misordered bytes; the decode pins of the
 *     pinned compiler (a header followed by static parameters, by a bytes
 *     parameter, exactly the header; 223 bytes -> AttestationHeaderMismatch;
 *     an expiry word with bit 64 set -> AttestationHeaderMismatch with data,
 *     not an empty revert); a starved precompile (a gas cap of a nested
 *     frame, found by a run-time scan) reverts MLDSA87InvalidSignature, i.e.
 *     the precompile call was REACHED and failed for lack of gas; the nonce mark is rolled back by a
 *     later revert in the same call and the same nonce then works with
 *     another signed message; re-entry with the same attestation is refused
 *     (AttestationNonceUsed recorded by the re-entering target);
 *     cancelAttestationNonce voids an unused nonce (then the attestation is
 *     refused), is refused for a used or already cancelled nonce, and touches
 *     only msg.sender's namespace; signer namespaces are independent; the
 *     2-of-3 action counts a signer once per proposal even under two nonces
 *     and executes at the second distinct signer, an outsider key is refused;
 *     the header-only action shows the README rule (a relayer chooses the
 *     unsigned amount and recipient). Pins: the mock's TAG_ATTEST_V1 view =
 *     the decision bytes 99e805e3...a43d; its PRECOMPILE view =
 *     evm_mldsa87_addr; the test TICKET differs from evm_mldsa87_addr; the
 *     two actionType constants (the compiler's compile-time keccak256) =
 *     the fixture's actiontype words (the tree's keccak256.c): the
 *     compiler-vs-tree hash check; the mock's pure message builders
 *     reproduce the bytes of test/fixtures/attest_v1.txt for both cases.
 *     With the switch OFF (the original state): verify returns ok == false
 *     for a VALID signature (an ordinary account, empty return) and the
 *     helper and an action revert MLDSA87InvalidSignature.
 *   Negative controls of the address width: every EOA address result is
 *   checked to differ from its 160-bit-masked value (ck_addr), every refusal
 *   that names an account names the full 32-byte account (the twin, not the
 *   original), and raw mapping slots of twins show no net write (the change
 *   set reports only slots whose value differs from the pre-state,
 *   evm.h:372-374, so a write that was later undone is not seen).
 *
 * WHAT IT REQUIRES
 *   The COMMITTED outputs nodus/tools/evm/contracts/out/<config>/
 *   <Contract>.{creation,runtime}.hex (written by contracts/build.sh with the
 *   pinned Nodus solc; contracts/verify.sh is the drift check); no solc at
 *   test time. Directory: argv[1], else CONTRACTS_OUT (default
 *   "../../nodus/tools/evm/contracts/out", relative to shared/evm, where
 *   `make test` runs it). A missing or malformed .hex is a FAIL, never a
 *   skip. No compile flags, no environment variables. The message fixture
 *   <dir>/../test/fixtures/attest_v1.txt (read at run time; missing = FAIL).
 *   The binary links the dsa signer (libevm_deps.a) and qgp_randombytes
 *   (tests/evm_test_qgp_shim.c), as test_mldsa_precompile does.
 *
 * ENGINE PROFILE
 *   As nodus_witness_rt_evm.c builds it (addr_bytes 32, nodus_profile 1,
 *   Prague precompiles, ticket unit 10^10, ticket gas 25000, base fee 0,
 *   gas price 0, type-1 txs, 32-byte chain id, coinbase zero). The ticket
 *   address is a fixed high-byte TEST constant (0x7e × 32), passed to the
 *   contracts as data — not the production SHA3-512("NDS.EVMWITHDRAW.v1")
 *   derivation. Block time is set per transaction (env.timestamp). Each
 *   configuration runs TWO engine states: the original one
 *   (mldsa_precompile 0) and one with mldsa_precompile 1 for the companion
 *   library (evm_state_new refuses that switch when the TICKET equals the
 *   tag address; the test asserts they differ).
 *
 * WHAT IT LEAVES BEHIND
 *   Nothing (in-memory backend, no files written).
 *
 * HOW IT CAN LIE
 *   - ML-DSA signatures are HEDGED: each run signs afresh, so signature
 *     bytes differ run to run. Every assertion is on an outcome (status,
 *     revert bytes, state, logs) or on message bytes, never on signature
 *     bytes; the gas-dependent assertion (the starved precompile) scans the
 *     gas cap of a nested frame at run time instead of hard-coding it. A
 *     top-level gas limit cannot reach that window (the tx's calldata floor,
 *     EIP-7623, is above it), hence the nested frame. If the scan finds no cap
 *     that reaches the precompile call and fails there, or never sees the
 *     call succeed at a larger cap, the test FAILS (it never passes
 *     vacuously).
 *   - "Another chain id" is a message built for another chain id (the
 *     consumer reads block.chainid from the one engine state); it proves the
 *     signed bytes bind the chain id, not that a second engine refuses.
 *   - The signing keys and the precompile are the project's own code
 *     (shared/crypto/sign/dsa, evm_precompile.c): a defect shared by signer
 *     and verifier would cancel out here; the NIST ACVP vectors of
 *     test_mldsa_precompile pin the verifier separately.
 *   - The fixture pins the ABI layout; its two hash words are copied inputs,
 *     the hash check is the compiler-vs-tree comparison above.
 *   - It tests the bytecode in out/, i.e. whatever solc wrote it; check
 *     out/VERSION.txt. A source edit without re-running build.sh leaves
 *     out/ stale: only contracts/verify.sh compares the .sol with the .hex,
 *     this test does not.
 *   - The engine is the shared/evm engine itself: an engine defect that
 *     mirrors a compiler defect would cancel out (test_addr32.c and
 *     test_nodus_profile.c pin the engine's 32-byte and ticket rules
 *     separately).
 *   - Not covered (engine / chain level): REDEEM of a ticket, the chain fee
 *     path, a chain-level gas price of zero, the envelope / receipt path of
 *     the node. The production ticket address is not used.
 *   - Abstract contracts are exercised only through the mocks listed above;
 *     a user contract that inherits them differently is not tested here.
 *
 * Standalone harness: exit 0 = every assertion in every configuration
 * passed, 1 = an assertion failed (or a .hex is missing), 2 = engine fault.
 */
#include "evm.h"
#include "evm_internal.h"
#include "evm_membackend.h"
#include "addr32_vectors.h"
#include "crypto/hash/keccak256.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/sign/qgp_dilithium.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef CONTRACTS_OUT
#define CONTRACTS_OUT "../../nodus/tools/evm/contracts/out"
#endif

#define TX_GAS     10000000ull
/* One evm_state_t is one block: the engine adds every tx's gas to
 * st->block_gas_used and refuses a tx whose gas_limit exceeds what is left
 * (evm_tx.c:190-192, EVM_TXERR_GAS_ALLOWANCE); there is no per-block reset in
 * the API. This test runs each configuration's whole scenario (hundreds of
 * txs) in ONE state, so the block budget must cover all of them. The block
 * gas cap is not under test here (the chain's cap is param 15, enforced by the
 * node); every tx keeps the per-tx limit TX_GAS. At 30 000 000 the scenario
 * ran out of block budget part-way (measured 2026-10-21: 26 / 23 txs refused
 * with tx_error 7 in default / optimize). */
#define BLOCK_GAS  (TX_GAS * 1000ull)
#define FUND_EOA   1000000000000000000ull      /* 10^18 wei = 10^8 q     */
#define Q          10000000000ull              /* 1 raw NODUS unit in wei */
#define T0         1760000000ull               /* first block time        */

/* ── fixed inputs: HIGH 12 bytes non-zero ──────────────────────────────── */

static void mk_addr(uint8_t out[32], uint8_t hi, uint8_t lo)
{
    memset(out, hi, 12);
    memset(out + 12, lo, 20);
}

/* S_SIG0..S_SIG3 are the ML-DSA-87 signers' own accounts (address =
 * SHA3-512(pk)[0..32], set by init_keys): cancelAttestationNonce is sent
 * from them. */
enum { S_A, S_A_TWIN, S_B, S_B_TWIN, S_C, S_C_TWIN, S_D, S_OUT, S_VIEW,
       S_SIG0, S_SIG1, S_SIG2, S_SIG3, S_COUNT };

static uint8_t ACC[S_COUNT][32];
#define A       ACC[S_A]
#define A_TWIN  ACC[S_A_TWIN]
#define B       ACC[S_B]
#define B_TWIN  ACC[S_B_TWIN]
#define C       ACC[S_C]
#define C_TWIN  ACC[S_C_TWIN]
#define D       ACC[S_D]
#define OUTSIDER ACC[S_OUT]

static uint8_t TICKET[32];      /* ticket address (test config): 0x7e*32 */
static uint8_t FP[64];          /* a destination fingerprint             */
static const uint8_t ZERO[32];

static uint8_t PROPOSER[32], EXECUTOR[32], CANCELLER[32];
static uint8_t ROLE_A[32], ROLE_B[32], ADMIN_B[32];

static void kec(const uint8_t *d, size_t n, uint8_t out[32]);

static void init_inputs(void)
{
    /* the four S_SIG slots are placeholders, replaced by init_keys() */
    static const uint8_t hi[S_COUNT] = { 0xa1, 0xc1, 0xa2, 0xc2, 0xa3, 0xc3,
                                         0xa4, 0xa5, 0xa9, 0xb0, 0xb1, 0xb2,
                                         0xb3 };
    static const uint8_t lo[S_COUNT] = { 0x11, 0x11, 0x22, 0x22, 0x33, 0x33,
                                         0x44, 0x55, 0x99, 0x01, 0x02, 0x03,
                                         0x04 };
    for (int i = 0; i < S_COUNT; i++) mk_addr(ACC[i], hi[i], lo[i]);
    memset(TICKET, 0x7e, 32);
    for (int i = 0; i < 64; i++) FP[i] = (uint8_t)(0x5a ^ i);
    kec((const uint8_t *)"PROPOSER_ROLE", 13, PROPOSER);
    kec((const uint8_t *)"EXECUTOR_ROLE", 13, EXECUTOR);
    kec((const uint8_t *)"CANCELLER_ROLE", 14, CANCELLER);
    kec((const uint8_t *)"ROLE_A", 6, ROLE_A);
    kec((const uint8_t *)"ROLE_B", 6, ROLE_B);
    kec((const uint8_t *)"ADMIN_B", 7, ADMIN_B);
}

/* ── small helpers ─────────────────────────────────────────────────────── */

static void fatal(const char *what)
{
    fprintf(stderr, "FATAL: %s\n", what);
    exit(2);
}

static void word_u64(uint8_t out[32], uint64_t v)
{
    memset(out, 0, 32);
    for (int i = 0; i < 8; i++) out[31 - i] = (uint8_t)(v >> (8 * i));
}

/* A word from a rotating pool, for building argument lists in one line. */
static const uint8_t *U(uint64_t v)
{
    static uint8_t pool[64][32];
    static unsigned k;
    uint8_t *w = pool[k++ % 64];
    word_u64(w, v);
    return w;
}

static void mask20(uint8_t out[32], const uint8_t in[32])
{
    memset(out, 0, 12);
    memcpy(out + 12, in + 12, 20);
}

static int high_nonzero(const uint8_t a[32])
{
    for (int i = 0; i < 12; i++)
        if (a[i]) return 1;
    return 0;
}

static void kec(const uint8_t *d, size_t n, uint8_t out[32])
{
    if (keccak256(d, n, out) != 0) fatal("keccak256");
}

static void print_word(const char *label, const uint8_t w[32])
{
    fprintf(stderr, "      %s ", label);
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", w[i]);
    fprintf(stderr, "\n");
}

/* CREATE = keccak256(rlp([sender32, nonce])) (engine design §2) */
static void create_addr(uint8_t out[32], const uint8_t sender[32], uint64_t nonce)
{
    uint8_t buf[64];
    uint8_t nb[8];
    size_t nl = 0, p = 0;
    for (int i = 7; i >= 0; i--) {
        uint8_t b = (uint8_t)(nonce >> (8 * i));
        if (nl || b) nb[nl++] = b;
    }
    size_t nenc = (nl == 1 && nb[0] < 0x80) ? 1 : 1 + nl;
    buf[p++] = (uint8_t)(0xc0 + 33 + nenc);
    buf[p++] = 0xa0;
    memcpy(buf + p, sender, 32);
    p += 32;
    if (nl == 1 && nb[0] < 0x80) {
        buf[p++] = nb[0];
    } else {
        buf[p++] = (uint8_t)(0x80 + nl);
        memcpy(buf + p, nb, nl);
        p += nl;
    }
    kec(buf, p, out);
}

/* The CREATE helper against the committed oracle vectors (as in
 * test_example_token.c): the self-address refusals below depend on it. */
static int self_check_rules(void)
{
    struct { const uint8_t *s; uint64_t n; const uint8_t *want; } v[] = {
        { ADDR32_FACTORY, 0x7f, ADDR32_EXP_CREATE_FACTORY_N7F },
        { ADDR32_FACTORY, 0x80, ADDR32_EXP_CREATE_FACTORY_N80 },
        { ADDR32_CREATOR0, ADDR32_NONCE_CREATOR0, ADDR32_EXP_TXCREATE_CREATOR0 },
        { ADDR32_CREATOR1, ADDR32_NONCE_CREATOR1, ADDR32_EXP_TXCREATE_CREATOR1 },
        { ADDR32_EF_FACTORY, ADDR32_NONCE_EF_FACTORY, ADDR32_EXP_CREATE_EF_FACTORY_N1 },
    };
    int bad = 0;
    uint8_t got[32];
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        create_addr(got, v[i].s, v[i].n);
        if (memcmp(got, v[i].want, 32) != 0) {
            fprintf(stderr, "  [FAIL] oracle: CREATE vector %u\n", (unsigned)i);
            bad = 1;
        }
    }
    fprintf(stderr, "oracle self-check of the CREATE helper: %s\n",
            bad ? "FAIL" : "PASS");
    return bad;
}

/* ── growable byte buffer + ABI encoder ────────────────────────────────── */

typedef struct {
    uint8_t *b;
    size_t   n, cap;
} buf_t;

static void buf_put(buf_t *x, const void *p, size_t n)
{
    if (n == 0) return;
    if (x->n + n > x->cap) {
        size_t nc = x->cap ? x->cap : 256;
        while (nc < x->n + n) nc *= 2;
        uint8_t *y = realloc(x->b, nc);
        if (!y) fatal("oom");
        x->b = y;
        x->cap = nc;
    }
    memcpy(x->b + x->n, p, n);
    x->n += n;
}

static void buf_free(buf_t *x)
{
    free(x->b);
    memset(x, 0, sizeof(*x));
}

#define ENC_MAX 8

/* Head/tail ABI encoding of one argument list (static words, `bytes`,
 * and `T[]` of static words). Encoded once by enc_out, which frees it. */
typedef struct {
    uint8_t head[ENC_MAX][32];
    int     dyn[ENC_MAX];
    size_t  tailpos[ENC_MAX];
    size_t  nh;
    buf_t   tail;
} enc_t;

static size_t enc_slot(enc_t *e)
{
    if (e->nh == ENC_MAX) fatal("encoder: too many arguments");
    return e->nh++;
}

static void enc_word(enc_t *e, const uint8_t w[32])
{
    size_t i = enc_slot(e);
    memcpy(e->head[i], w, 32);
}

static void enc_bytes(enc_t *e, const uint8_t *d, size_t n)
{
    static const uint8_t zpad[32];
    size_t i = enc_slot(e);
    e->dyn[i] = 1;
    e->tailpos[i] = e->tail.n;
    buf_put(&e->tail, U(n), 32);
    buf_put(&e->tail, d, n);
    if (n % 32) buf_put(&e->tail, zpad, 32 - n % 32);
}

static void enc_words(enc_t *e, const uint8_t *const *w, size_t n)
{
    size_t i = enc_slot(e);
    e->dyn[i] = 1;
    e->tailpos[i] = e->tail.n;
    buf_put(&e->tail, U(n), 32);
    for (size_t k = 0; k < n; k++) buf_put(&e->tail, w[k], 32);
}

static void enc_out(enc_t *e, buf_t *out)
{
    for (size_t i = 0; i < e->nh; i++)
        buf_put(out, e->dyn[i] ? U(e->nh * 32 + e->tailpos[i]) : e->head[i], 32);
    if (e->tail.n) buf_put(out, e->tail.b, e->tail.n);
    buf_free(&e->tail);
}

static enc_t E0(void)
{
    enc_t e;
    memset(&e, 0, sizeof(e));
    return e;
}

/* An encoder of `n` static words given as pointers. */
static enc_t EW(const uint8_t *const *w, size_t n)
{
    enc_t e = E0();
    for (size_t i = 0; i < n; i++) enc_word(&e, w[i]);
    return e;
}

/* ARGS(x, y, ...) -> pointer array, count */
#define PTRS(...) ((const uint8_t *const[]){ __VA_ARGS__ })
#define ARGS(...) PTRS(__VA_ARGS__), (sizeof(PTRS(__VA_ARGS__)) / sizeof(const uint8_t *))
#define E(...)    EW(ARGS(__VA_ARGS__))

static void sel_of(const char *sig, uint8_t out[4])
{
    uint8_t h[32];
    kec((const uint8_t *)sig, strlen(sig), h);
    memcpy(out, h, 4);
}

/* calldata = selector(sig) ‖ abi(args) */
static void mk_call(buf_t *out, const char *sig, enc_t e)
{
    uint8_t s[4];
    memset(out, 0, sizeof(*out));
    sel_of(sig, s);
    buf_put(out, s, 4);
    enc_out(&e, out);
}

/* ── .hex loading ──────────────────────────────────────────────────────── */

typedef struct {
    uint8_t *b;
    size_t   n;
} blob_t;

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* @return 0, -1 missing / unreadable / malformed (message printed) */
static int load_hex(const char *dir, const char *cfg, const char *name,
                    const char *kind, blob_t *out)
{
    char path[1024];
    out->b = NULL;
    out->n = 0;
    int pn = snprintf(path, sizeof(path), "%s/%s/%s.%s.hex", dir, cfg, name, kind);
    if (pn < 0 || (size_t)pn >= sizeof(path)) {
        fprintf(stderr, "  [FAIL] %s: path too long\n", cfg);
        return -1;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "  [FAIL] %s: missing %s\n", cfg, path);
        return -1;
    }
    size_t cap = 4096, n = 0;
    char *txt = malloc(cap);
    if (!txt) fatal("oom");
    int ch;
    while ((ch = fgetc(f)) != EOF) {
        if (ch == '\n' || ch == '\r' || ch == ' ' || ch == '\t') continue;
        if (n + 1 >= cap) {
            cap *= 2;
            char *x = realloc(txt, cap);
            if (!x) fatal("oom");
            txt = x;
        }
        txt[n++] = (char)ch;
    }
    fclose(f);
    if (n == 0 || n % 2 != 0) {
        fprintf(stderr, "  [FAIL] %s: %s is empty or has an odd length\n", cfg, path);
        free(txt);
        return -1;
    }
    out->b = malloc(n / 2);
    if (!out->b) fatal("oom");
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(txt[2 * i]), lo = hexval(txt[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            fprintf(stderr, "  [FAIL] %s: %s is not hex\n", cfg, path);
            free(txt);
            free(out->b);
            out->b = NULL;
            return -1;
        }
        out->b[i] = (uint8_t)(hi * 16 + lo);
    }
    out->n = n / 2;
    free(txt);
    return 0;
}

/* ── per-configuration context ─────────────────────────────────────────── */

enum { K_TIMELOCK, K_VAULT, K_ESCROW, K_OWNABLE, K_AC, K_GUARDED, K_ACTOR,
       K_FALSE, K_TICKETSENDER, K_FORCER, K_ATTESTED, K_COUNT };

static const char *const NAMES[K_COUNT] = {
    "Timelock", "MultisigVault", "MilestoneEscrow", "MockOwnable",
    "MockAccessControl", "MockGuarded", "MockActor", "MockFalseTarget",
    "MockTicketSender", "MockForcer", "MockAttested",
};

#define MAX_DEPLOYED 64

typedef struct {
    const char     *cfg;
    unsigned        pass, fail;
    blob_t          creation[K_COUNT], runtime[K_COUNT];
    int             dep_kind[MAX_DEPLOYED];
    uint8_t         dep_addr[MAX_DEPLOYED][32];
    size_t          ndep;
    evm_membackend  mb;
    evm_backend_t   be;
    evm_config_t    ec;
    evm_block_env_t env;
    evm_state_t    *st;
    uint64_t        nonce[S_COUNT];
} ctx_t;

static void ck(ctx_t *c, int cond, const char *what)
{
    if (cond) {
        c->pass++;
    } else {
        c->fail++;
        fprintf(stderr, "  [FAIL] %s: %s\n", c->cfg, what);
    }
}

/* got == want, want has non-zero high bytes, got is NOT the 160-bit-masked
 * value (the negative control of every EOA address check). */
static void ck_addr(ctx_t *c, const uint8_t got[32], const uint8_t want[32],
                    const char *what)
{
    uint8_t masked[32];
    mask20(masked, want);
    int eq = memcmp(got, want, 32) == 0;
    int hi = high_nonzero(want);
    int not_masked = memcmp(got, masked, 32) != 0;
    if (eq && hi && not_masked) {
        c->pass++;
        return;
    }
    c->fail++;
    fprintf(stderr, "  [FAIL] %s: %s%s%s%s\n", c->cfg, what,
            eq ? "" : " (value differs)",
            hi ? "" : " (expected value has zero high bytes: premise broken)",
            not_masked ? "" : " (equals the 160-bit-masked value)");
    print_word("got ", got);
    print_word("want", want);
}

static void ck_word(ctx_t *c, const uint8_t got[32], const uint8_t want[32],
                    const char *what)
{
    if (memcmp(got, want, 32) == 0) {
        c->pass++;
        return;
    }
    c->fail++;
    fprintf(stderr, "  [FAIL] %s: %s\n", c->cfg, what);
    print_word("got ", got);
    print_word("want", want);
}

static void ck_u64(ctx_t *c, const uint8_t got[32], uint64_t want, const char *what)
{
    ck_word(c, got, U(want), what);
}

static void ck_u64v(ctx_t *c, uint64_t got, uint64_t want, const char *what)
{
    if (got == want) {
        c->pass++;
        return;
    }
    c->fail++;
    fprintf(stderr, "  [FAIL] %s: %s (got %llu, want %llu)\n", c->cfg, what,
            (unsigned long long)got, (unsigned long long)want);
}

/* A `bytes4` return word = the selector of `sig`, left-aligned. */
static void ck_sel(ctx_t *c, const uint8_t got[32], const char *sig, const char *what)
{
    uint8_t w[32];
    memset(w, 0, 32);
    sel_of(sig, w);
    ck_word(c, got, w, what);
}

/* ── transactions ──────────────────────────────────────────────────────── */

/* type-1 tx from sender s, gas price 0 (Nodus profile); to NULL = create.
 * @return evm_tx_apply's rc; a fault is fatal. */
static int send_tx(ctx_t *c, int s, const uint8_t *to, uint64_t value,
                   const buf_t *d, evm_tx_result_t *res)
{
    evm_tx_t tx;
    memset(&tx, 0, sizeof(tx));
    memset(res, 0, sizeof(*res));
    tx.type = 1;
    memcpy(tx.sender.b, ACC[s], 32);
    if (to) memcpy(tx.to.b, to, 32);
    else tx.is_create = 1;
    tx.nonce = c->nonce[s];
    tx.gas_limit = TX_GAS;
    evm_u256_from_u64(&tx.value, value);
    tx.data = d ? d->b : NULL;
    tx.data_len = d ? d->n : 0;
    tx.has_chain_id = 1;
    tx.chain_id = c->ec.chain_id;
    tx.intent_id[0] = (uint8_t)s;
    for (int i = 0; i < 8; i++) tx.intent_id[1 + i] = (uint8_t)(c->nonce[s] >> (8 * i));
    int rc = evm_tx_apply(c->st, &c->env, &tx, res);
    if (rc == -2) fatal("evm_tx_apply fault");
    if (rc == 0) c->nonce[s]++;
    return rc;
}

/* Must SUCCEED. r NULL: the result is freed here.
 * @return 1 ok (r owned by the caller when given), 0 failed (r freed). */
static int ok_tx(ctx_t *c, int s, const uint8_t *to, uint64_t v, const buf_t *d,
                 evm_tx_result_t *r, const char *what)
{
    evm_tx_result_t own;
    evm_tx_result_t *res = r ? r : &own;
    int rc = send_tx(c, s, to, v, d, res);
    int ok = rc == 0 && res->status == EVM_EXEC_SUCCESS;
    if (ok) {
        c->pass++;
    } else {
        c->fail++;
        fprintf(stderr, "  [FAIL] %s: %s: rc %d tx_error %d status %d output %u bytes\n",
                c->cfg, what, rc, (int)res->tx_error, (int)res->status,
                (unsigned)res->output_len);
        if (res->output_len >= 4)
            fprintf(stderr, "      revert selector %02x%02x%02x%02x\n", res->output[0],
                    res->output[1], res->output[2], res->output[3]);
    }
    if (!ok || !r) evm_tx_result_free(res);
    return ok;
}

/* Must REVERT with exactly the output `want` (NULL: any revert output).
 * The n_logs == 0 && n_tickets == 0 conjuncts are ENGINE-GUARANTEED on a
 * revert, not a property of the contract under test: evm_tx_apply copies
 * logs and tickets into the result only when the top frame succeeded
 * (shared/evm/evm_tx.c:432, :445). They are kept as a cheap tripwire on that
 * engine rule; they cannot fail because of a contract. `wdesc` names the
 * expected error in the failure message. */
static void rev_exact(ctx_t *c, int s, const uint8_t *to, uint64_t v, const buf_t *d,
                      const buf_t *want, const char *wdesc, const char *what)
{
    evm_tx_result_t r;
    int rc = send_tx(c, s, to, v, d, &r);
    int ok = rc == 0 && r.status == EVM_EXEC_REVERT && r.n_logs == 0 &&
             r.n_tickets == 0;
    if (ok && want)
        ok = r.output_len == want->n &&
             (want->n == 0 || memcmp(r.output, want->b, want->n) == 0);
    if (ok) {
        c->pass++;
    } else {
        c->fail++;
        fprintf(stderr, "  [FAIL] %s: %s: rc %d status %d logs %u tickets %u output "
                "%u bytes (want REVERT %s; no log / no ticket is engine-guaranteed "
                "on a revert)\n", c->cfg, what, rc, (int)r.status,
                (unsigned)r.n_logs, (unsigned)r.n_tickets, (unsigned)r.output_len,
                wdesc ? wdesc : "(any)");
        if (r.output_len >= 4)
            fprintf(stderr, "      selector %02x%02x%02x%02x\n", r.output[0],
                    r.output[1], r.output[2], r.output[3]);
        for (size_t i = 0; i < 6 && 4 + 32 * (i + 1) <= r.output_len; i++)
            print_word("arg ", r.output + 4 + 32 * i);
    }
    evm_tx_result_free(&r);
}

/* Must REVERT with the custom error `esig(args...)` of static words (exact
 * output). esig NULL: any revert output. */
static void rev_tx(ctx_t *c, int s, const uint8_t *to, uint64_t v, const buf_t *d,
                   const char *esig, const uint8_t *const *args, size_t nargs,
                   const char *what)
{
    buf_t want;
    memset(&want, 0, sizeof(want));
    if (esig) {
        uint8_t sel[4];
        sel_of(esig, sel);
        buf_put(&want, sel, 4);
        for (size_t i = 0; i < nargs; i++) buf_put(&want, args[i], 32);
    }
    rev_exact(c, s, to, v, d, esig ? &want : NULL, esig, what);
    buf_free(&want);
}

/* The exact output of a generic executor's failure error
 * `outer(id, bytes reason)` (TimelockCallFailed / VaultCallFailed), where
 * reason = the target's revert data: inner_sig's selector ‖ its static-word
 * args, or empty when inner_sig is NULL (a halted frame — e.g. a refused
 * ticket call — returns no data, evm_interp.c halt()). */
static void mk_wrapped(buf_t *out, const char *outer, const uint8_t id[32],
                       const char *inner_sig, const uint8_t *const *iargs, size_t ni)
{
    buf_t inner;
    memset(&inner, 0, sizeof(inner));
    if (inner_sig) {
        uint8_t sel[4];
        sel_of(inner_sig, sel);
        buf_put(&inner, sel, 4);
        for (size_t i = 0; i < ni; i++) buf_put(&inner, iargs[i], 32);
    }
    enc_t e = E0();
    enc_word(&e, id);
    enc_bytes(&e, inner.b, inner.n);
    mk_call(out, outer, e);
    buf_free(&inner);
}

static int call_ok(ctx_t *c, int s, const uint8_t *to, uint64_t v, const char *sig,
                   enc_t e, evm_tx_result_t *r, const char *what)
{
    buf_t d;
    mk_call(&d, sig, e);
    int ok = ok_tx(c, s, to, v, &d, r, what);
    buf_free(&d);
    return ok;
}

static void call_rev(ctx_t *c, int s, const uint8_t *to, uint64_t v, const char *sig,
                     enc_t e, const char *esig, const uint8_t *const *args,
                     size_t nargs, const char *what)
{
    buf_t d;
    mk_call(&d, sig, e);
    rev_tx(c, s, to, v, &d, esig, args, nargs, what);
    buf_free(&d);
}

/* call `sig(e)` must REVERT with outer(id, reason = inner_sig(iargs...)),
 * exact bytes (see mk_wrapped). */
static void call_rev_wrapped(ctx_t *c, int s, const uint8_t *to, const char *sig, enc_t e,
                             const char *outer, const uint8_t id[32],
                             const char *inner_sig, const uint8_t *const *iargs,
                             size_t ni, const char *what)
{
    buf_t d, want;
    char desc[200];
    mk_call(&d, sig, e);
    mk_wrapped(&want, outer, id, inner_sig, iargs, ni);
    snprintf(desc, sizeof(desc), "%s with reason %s", outer, inner_sig ? inner_sig : "(empty)");
    rev_exact(c, s, to, 0, &d, &want, desc, what);
    buf_free(&want);
    buf_free(&d);
}

/* A view: word `idx` of the output into out (0xee.. on failure). */
static void view_at(ctx_t *c, const uint8_t *to, const char *sig, enc_t e,
                    size_t idx, uint8_t out[32], const char *what)
{
    evm_tx_result_t r;
    memset(out, 0xee, 32);                 /* never equals an expected value */
    if (!call_ok(c, S_VIEW, to, 0, sig, e, &r, what)) return;
    if (r.output_len >= 32 * (idx + 1)) memcpy(out, r.output + 32 * idx, 32);
    else ck(c, 0, what);
    evm_tx_result_free(&r);
}

static void view(ctx_t *c, const uint8_t *to, const char *sig, enc_t e,
                 uint8_t out[32], const char *what)
{
    view_at(c, to, sig, e, 0, out, what);
}

/* ── deployment ────────────────────────────────────────────────────────── */

static void mk_create(buf_t *out, const blob_t *creation, enc_t e)
{
    memset(out, 0, sizeof(*out));
    buf_put(out, creation->b, creation->n);
    enc_out(&e, out);
}

/* Deploy `kind` with constructor args `e` and `value`. Checks the CREATE
 * address and records it for the final runtime comparison.
 * @return 0 ok (addr filled; r owned by the caller when given), -1 failed. */
static int deploy(ctx_t *c, int s, int kind, enc_t e, uint64_t value,
                  uint8_t addr[32], evm_tx_result_t *r, const char *what)
{
    buf_t d;
    uint8_t want[32];
    evm_tx_result_t own;
    evm_tx_result_t *res = r ? r : &own;
    mk_create(&d, &c->creation[kind], e);
    create_addr(want, ACC[s], c->nonce[s]);
    int ok = ok_tx(c, s, NULL, value, &d, res, what);
    buf_free(&d);
    memset(addr, 0xee, 32);
    if (!ok) return -1;
    ck_word(c, res->created.b, want, "deployed at the CREATE address (sender32, nonce)");
    memcpy(addr, res->created.b, 32);
    if (c->ndep == MAX_DEPLOYED) fatal("too many deployments");
    c->dep_kind[c->ndep] = kind;
    memcpy(c->dep_addr[c->ndep], addr, 32);
    c->ndep++;
    if (!r) evm_tx_result_free(res);
    return 0;
}

static void deploy_rev(ctx_t *c, int s, int kind, enc_t e, const char *esig,
                       const uint8_t *const *args, size_t nargs, const char *what)
{
    buf_t d;
    mk_create(&d, &c->creation[kind], e);
    rev_tx(c, s, NULL, 0, &d, esig, args, nargs, what);
    buf_free(&d);
}

/* ── logs and tickets ──────────────────────────────────────────────────── */

/* one of the test EOAs (their address checks go through ck_addr) */
static int is_eoa(const uint8_t w[32])
{
    for (int i = 0; i < S_COUNT; i++)
        if (memcmp(w, ACC[i], 32) == 0) return 1;
    return 0;
}

static const evm_log_t *find_log(const evm_tx_result_t *r, const uint8_t em[32],
                                 const char *sig)
{
    uint8_t t0[32];
    kec((const uint8_t *)sig, strlen(sig), t0);
    for (size_t i = 0; i < r->n_logs; i++)
        if (memcmp(r->logs[i].addr.b, em, 32) == 0 && r->logs[i].n_topics > 0 &&
            memcmp(r->logs[i].topics[0].b, t0, 32) == 0)
            return &r->logs[i];
    return NULL;
}

/* A log `sig` from `em` with exactly 1 + nt topics; topic i+1 = t[i]
 * (an EOA address topic through ck_addr: the full 32 bytes, not masked).
 * When a tx emits several logs of one event (the Timelock constructor's
 * RoleGranted), the log is picked by its first indexed topic t[0]. */
static void ck_log(ctx_t *c, const evm_tx_result_t *r, const uint8_t em[32],
                   const char *sig, const uint8_t *const *t, size_t nt,
                   const char *what)
{
    char m[200];
    uint8_t t0[32];
    const evm_log_t *l = NULL;
    kec((const uint8_t *)sig, strlen(sig), t0);
    for (size_t i = 0; i < r->n_logs && !l; i++) {
        const evm_log_t *x = &r->logs[i];
        if (memcmp(x->addr.b, em, 32) == 0 && x->n_topics == nt + 1 &&
            memcmp(x->topics[0].b, t0, 32) == 0 &&
            (nt == 0 || memcmp(x->topics[1].b, t[0], 32) == 0))
            l = x;
    }
    snprintf(m, sizeof(m), "%s: log %s with %u topics", what, sig, (unsigned)(nt + 1));
    ck(c, l && l->n_topics == nt + 1, m);
    if (!l || l->n_topics != nt + 1) return;
    for (size_t i = 0; i < nt; i++) {
        snprintf(m, sizeof(m), "%s: topic %u", what, (unsigned)(i + 1));
        if (is_eoa(t[i]))
            ck_addr(c, l->topics[i + 1].b, t[i], m);
        else
            ck_word(c, l->topics[i + 1].b, t[i], m);
    }
}

static void ck_no_log(ctx_t *c, const evm_tx_result_t *r, const char *what)
{
    ck(c, r->n_logs == 0, what);
}

/* exactly one ticket: `amount` wei to FP-like `fp` */
static void ck_ticket(ctx_t *c, const evm_tx_result_t *r, uint64_t amount,
                      const uint8_t fp[64], const char *what)
{
    char m[200];
    snprintf(m, sizeof(m), "%s: exactly one ticket", what);
    ck(c, r->n_tickets == 1, m);
    if (r->n_tickets != 1) return;
    uint8_t got[32];
    evm_u256_to_be(got, &r->tickets[0].amount_wei);
    snprintf(m, sizeof(m), "%s: ticket amount", what);
    ck_u64(c, got, amount, m);
    snprintf(m, sizeof(m), "%s: ticket destination = the 64-byte fingerprint", what);
    ck(c, memcmp(r->tickets[0].dest_fp, fp, 64) == 0, m);
}

/* ── post-state (change set over the pre-state) ────────────────────────── */

typedef struct {
    int      found;
    uint8_t  balance[32];
    int      code_found;
    uint8_t *code;
    size_t   code_len;
    const uint8_t *addr;
    const uint8_t *key;          /* storage query, or NULL */
    int      slot_found;
    uint8_t  slot[32];
} probe_t;

static int cb_account(void *ctx, const evm_account_change_t *ch)
{
    probe_t *p = ctx;
    if (memcmp(ch->addr.b, p->addr, 32) != 0) return 0;
    p->found = 1;
    evm_u256_to_be(p->balance, &ch->balance);
    if (ch->code_changed) {
        p->code_found = 1;
        free(p->code);
        p->code = NULL;
        p->code_len = ch->code_len;
        if (ch->code_len) {
            p->code = malloc(ch->code_len);
            if (!p->code) fatal("oom");
            memcpy(p->code, ch->code, ch->code_len);
        }
    }
    return 0;
}

static int cb_storage(void *ctx, const evm_addr *addr, const evm_bytes32 *key,
                      const evm_bytes32 *value)
{
    probe_t *p = ctx;
    if (p->key && memcmp(addr->b, p->addr, 32) == 0 &&
        memcmp(key->b, p->key, 32) == 0) {
        p->slot_found = 1;
        memcpy(p->slot, value->b, 32);
    }
    return 0;
}

static void probe(const ctx_t *c, probe_t *p, const uint8_t addr[32],
                  const uint8_t *key)
{
    memset(p, 0, sizeof(*p));
    p->addr = addr;
    p->key = key;
    evm_change_visitor_t v;
    v.account = cb_account;
    v.storage = cb_storage;
    v.ctx = p;
    if (evm_state_visit_changes(c->st, &v) != 0) fatal("visit_changes");
}

/* Post balance of a touched account (u64: every balance here fits). */
static uint64_t bal(ctx_t *c, const uint8_t addr[32])
{
    probe_t p;
    probe(c, &p, addr, NULL);
    free(p.code);
    uint64_t v = 0;
    for (int i = 0; i < 24; i++)
        if (p.balance[i]) fatal("balance above 2^64");
    for (int i = 24; i < 32; i++) v = (v << 8) | p.balance[i];
    return v;
}

/* @return 1 when the txs wrote the slot (value in out), else 0 (out = 0) */
static int raw_slot(ctx_t *c, const uint8_t addr[32], const uint8_t key[32],
                    uint8_t out[32])
{
    probe_t p;
    probe(c, &p, addr, key);
    free(p.code);
    memcpy(out, p.slot_found ? p.slot : ZERO, 32);
    return p.slot_found;
}

/* key = keccak256(k32 ‖ word) — the mapping slot rule */
static void slot_map(uint8_t key[32], const uint8_t k[32], const uint8_t slot[32])
{
    uint8_t buf[64];
    memcpy(buf, k, 32);
    memcpy(buf + 32, slot, 32);
    kec(buf, 64, key);
}

/* ── setup ─────────────────────────────────────────────────────────────── */

static void chain_id_word(evm_u256 *out)
{
    uint8_t b[32];
    for (int i = 0; i < 32; i++) b[i] = (uint8_t)(0xc0 + i);
    evm_u256_from_be(out, b);
}

static void add_eoa(evm_membackend *mb, const uint8_t a[32], uint64_t balance)
{
    evm_addr x;
    memcpy(x.b, a, 32);
    if (evm_membackend_add_account(mb, &x, 0, U(balance), NULL, 0, NULL, NULL) != 0)
        fatal("membackend add");
}

/* mldsa: the engine's mldsa_precompile switch (0 = the original state, 1 =
 * the companion-library state). */
static int ctx_open(ctx_t *c, const char *dir, const char *cfg, int mldsa)
{
    memset(c, 0, sizeof(*c));
    c->cfg = cfg;
    int missing = 0;
    for (int k = 0; k < K_COUNT; k++) {
        if (load_hex(dir, cfg, NAMES[k], "creation", &c->creation[k]) != 0) missing++;
        if (load_hex(dir, cfg, NAMES[k], "runtime", &c->runtime[k]) != 0) missing++;
    }
    if (missing) {
        c->fail += (unsigned)missing;
        return -1;
    }

    evm_membackend_init(&c->mb);
    for (int s = 0; s < S_COUNT; s++) add_eoa(&c->mb, ACC[s], FUND_EOA);
    if (evm_membackend_finalize(&c->mb) != 0) fatal("membackend finalize");
    evm_membackend_bind(&c->mb, &c->be);

    /* nodus_witness_rt_evm.c (the node's EVM configuration) */
    c->ec.fork = EVM_FORK_PRAGUE;
    c->ec.addr_bytes = 32;
    chain_id_word(&c->ec.chain_id);
    c->ec.precompile_mask = EVM_PRECOMPILES_PRAGUE;
    c->ec.nodus_profile = 1;
    memcpy(c->ec.ticket_addr.b, TICKET, 32);
    evm_u256_from_u64(&c->ec.ticket_unit, Q);
    c->ec.ticket_gas = 25000;
    c->ec.mldsa_precompile = mldsa;

    /* coinbase zero, as in production */
    c->env.number = 1000;
    c->env.timestamp = T0;
    c->env.gas_limit = BLOCK_GAS;
    evm_u256_zero(&c->env.base_fee);

    c->st = evm_state_new(&c->ec, &c->be);
    if (!c->st) fatal("evm_state_new");
    return 0;
}

static void ctx_close(ctx_t *c)
{
    for (int k = 0; k < K_COUNT; k++) {
        free(c->creation[k].b);
        free(c->runtime[k].b);
    }
    if (c->st) evm_state_free(c->st);
    evm_membackend_free(&c->mb);
}

/* Advance block time (and height) — later blocks only. */
static void at_time(ctx_t *c, uint64_t t)
{
    if (t < c->env.timestamp) fatal("block time must not go back");
    if (t > c->env.timestamp) c->env.number++;
    c->env.timestamp = t;
}

/* ── shared mock helpers ───────────────────────────────────────────────── */

#define MODE_ACCEPT  0
#define MODE_REVERT  1
#define MODE_REENTER 2

static void actor_mode(ctx_t *c, const uint8_t actor[32], uint64_t mode,
                       const uint8_t *target, const buf_t *data)
{
    enc_t e = E0();
    enc_word(&e, U(mode));
    enc_word(&e, target ? target : ZERO);
    enc_bytes(&e, data ? data->b : NULL, data ? data->n : 0);
    call_ok(c, S_OUT, actor, 0, "setMode(uint8,address,bytes)", e, NULL,
            "MockActor.setMode");
}

/* actor.act(target, 0, data): the actor calls `target` and records it */
static void actor_act(ctx_t *c, const uint8_t actor[32], const uint8_t target[32],
                      const buf_t *data, evm_tx_result_t *r, const char *what)
{
    enc_t e = E0();
    enc_word(&e, target);
    enc_word(&e, U(0));
    enc_bytes(&e, data->b, data->n);
    call_ok(c, S_OUT, actor, 0, "act(address,uint256,bytes)", e, r, what);
}

static void mk_hook(buf_t *out)
{
    mk_call(out, "hook()", E0());
}

/* ── Ownable ───────────────────────────────────────────────────────────── */

static void scen_ownable(ctx_t *c)
{
    static const char *UNAUTH = "OwnableUnauthorizedAccount(address)";
    static const char *INVALID = "OwnableInvalidOwner(address)";
    uint8_t own[32], w[32], key[32];
    evm_tx_result_t r;

    deploy_rev(c, S_A, K_OWNABLE, E(ZERO), INVALID, ARGS(ZERO),
               "MockOwnable(address(0)) refused");
    if (deploy(c, S_A, K_OWNABLE, E(A), 0, own, &r, "deploy MockOwnable(A)") != 0)
        return;
    ck_log(c, &r, own, "OwnershipTransferred(address,address)", ARGS(ZERO, A),
           "constructor");
    evm_tx_result_free(&r);
    view(c, own, "owner()", E0(), w, "owner()");
    ck_addr(c, w, A, "owner() = A (full 32 bytes)");
    view(c, own, "pendingOwner()", E0(), w, "pendingOwner()");
    ck_word(c, w, ZERO, "pendingOwner() = 0 after deploy");

    call_ok(c, S_A, own, 0, "setValue(uint256)", E(U(7)), NULL, "setValue by the owner");
    call_rev(c, S_A_TWIN, own, 0, "setValue(uint256)", E(U(8)), UNAUTH, ARGS(A_TWIN),
             "setValue by the owner's twin refused (error names the twin)");
    call_rev(c, S_B, own, 0, "transferOwnership(address)", E(B), UNAUTH, ARGS(B),
             "transferOwnership by a non-owner refused");
    call_rev(c, S_A, own, 0, "transferOwnership(address)", E(ZERO), INVALID, ARGS(ZERO),
             "transferOwnership(0) refused");

    if (call_ok(c, S_A, own, 0, "transferOwnership(address)", E(B), &r,
                "transferOwnership(B) by the owner")) {
        ck_log(c, &r, own, "OwnershipTransferStarted(address,address)", ARGS(A, B),
               "nominate B");
        evm_tx_result_free(&r);
    }
    view(c, own, "pendingOwner()", E0(), w, "pendingOwner()");
    ck_addr(c, w, B, "pendingOwner() = B");
    view(c, own, "owner()", E0(), w, "owner()");
    ck_addr(c, w, A, "owner() still A while B has not accepted");

    call_rev(c, S_C, own, 0, "acceptOwnership()", E0(), UNAUTH, ARGS(C),
             "acceptOwnership by a non-nominee refused");
    call_rev(c, S_B_TWIN, own, 0, "acceptOwnership()", E0(), UNAUTH, ARGS(B_TWIN),
             "acceptOwnership by the nominee's twin refused");

    call_ok(c, S_A, own, 0, "transferOwnership(address)", E(C), NULL,
            "second nomination (C) overwrites B");
    call_rev(c, S_B, own, 0, "acceptOwnership()", E0(), UNAUTH, ARGS(B),
             "acceptOwnership by the stale nominee B refused");
    if (call_ok(c, S_C, own, 0, "acceptOwnership()", E0(), &r, "acceptOwnership by C")) {
        ck_log(c, &r, own, "OwnershipTransferred(address,address)", ARGS(A, C),
               "accept");
        evm_tx_result_free(&r);
    }
    view(c, own, "owner()", E0(), w, "owner()");
    ck_addr(c, w, C, "owner() = C");
    view(c, own, "pendingOwner()", E0(), w, "pendingOwner()");
    ck_word(c, w, ZERO, "pendingOwner() cleared");
    call_rev(c, S_A, own, 0, "setValue(uint256)", E(U(9)), UNAUTH, ARGS(A),
             "the former owner is refused");
    call_ok(c, S_C, own, 0, "setValue(uint256)", E(U(10)), NULL, "setValue by the new owner");
    view(c, own, "value()", E0(), w, "value()");
    ck_u64(c, w, 10, "value() = 10");

    /* raw storage (solc --storage-layout: slot 0 _owner, slot 1 _pendingOwner) */
    raw_slot(c, own, U(0), w);
    ck_addr(c, w, C, "raw slot 0 = the owner's full 32 bytes");
    ck(c, !raw_slot(c, own, U(1), key), "raw slot 1 (pendingOwner) is zero again");
}

/* ── AccessControl ─────────────────────────────────────────────────────── */

/* raw slot of hasRole[role][account]: keccak256(account ‖ keccak256(role ‖ slot)) */
static void role_slot(uint8_t key[32], const uint8_t role[32], const uint8_t acct[32],
                      uint64_t slot)
{
    uint8_t inner[32];
    slot_map(inner, role, U(slot));
    slot_map(key, acct, inner);
}

static void scen_access(ctx_t *c)
{
    static const char *UNAUTH = "AccessControlUnauthorizedAccount(address,bytes32)";
    static const char *GRANTED = "RoleGranted(bytes32,address,address)";
    uint8_t ac[32], w[32], key[32];
    evm_tx_result_t r;

    if (deploy(c, S_A, K_AC, E(A), 0, ac, &r, "deploy MockAccessControl(A)") != 0)
        return;
    ck_log(c, &r, ac, GRANTED, ARGS(ZERO, A, A), "constructor grant of DEFAULT_ADMIN_ROLE");
    ck_log(c, &r, ac, "RoleAdminChanged(bytes32,bytes32,bytes32)",
           ARGS(ROLE_B, ZERO, ADMIN_B), "constructor ROLE_B admin = ADMIN_B");
    evm_tx_result_free(&r);

    view(c, ac, "hasRole(bytes32,address)", E(ZERO, A), w, "hasRole");
    ck_u64(c, w, 1, "A holds DEFAULT_ADMIN_ROLE");
    view(c, ac, "hasRole(bytes32,address)", E(ZERO, A_TWIN), w, "hasRole");
    ck_u64(c, w, 0, "A's twin does not hold DEFAULT_ADMIN_ROLE");

    call_rev(c, S_C, ac, 0, "grantRole(bytes32,address)", E(ROLE_A, B), UNAUTH,
             ARGS(C, ZERO), "grantRole by a non-admin refused");
    call_rev(c, S_A_TWIN, ac, 0, "grantRole(bytes32,address)", E(ROLE_A, B), UNAUTH,
             ARGS(A_TWIN, ZERO), "grantRole by the admin's twin refused");
    if (call_ok(c, S_A, ac, 0, "grantRole(bytes32,address)", E(ROLE_A, B), &r,
                "grantRole(ROLE_A, B) by the admin")) {
        ck_log(c, &r, ac, GRANTED, ARGS(ROLE_A, B, A), "grant ROLE_A");
        evm_tx_result_free(&r);
    }
    if (call_ok(c, S_A, ac, 0, "grantRole(bytes32,address)", E(ROLE_A, B), &r,
                "grantRole(ROLE_A, B) again")) {
        ck_no_log(c, &r, "a repeated grant is a no-op without an event");
        evm_tx_result_free(&r);
    }
    call_ok(c, S_B, ac, 0, "useA()", E0(), NULL, "useA by the ROLE_A holder");
    call_rev(c, S_B_TWIN, ac, 0, "useA()", E0(), UNAUTH, ARGS(B_TWIN, ROLE_A),
             "useA by the holder's twin refused");
    call_rev(c, S_C, ac, 0, "revokeRole(bytes32,address)", E(ROLE_A, B), UNAUTH,
             ARGS(C, ZERO), "revokeRole by a non-admin refused");
    call_rev(c, S_C, ac, 0, "renounceRole(bytes32,address)", E(ROLE_A, B),
             "AccessControlBadConfirmation()", NULL, 0,
             "renounceRole for another account refused");

    /* role-admin isolation */
    view(c, ac, "getRoleAdmin(bytes32)", E(ROLE_B), w, "getRoleAdmin(ROLE_B)");
    ck_word(c, w, ADMIN_B, "getRoleAdmin(ROLE_B) = ADMIN_B");
    view(c, ac, "getRoleAdmin(bytes32)", E(ROLE_A), w, "getRoleAdmin(ROLE_A)");
    ck_word(c, w, ZERO, "getRoleAdmin(ROLE_A) = DEFAULT_ADMIN_ROLE");
    call_rev(c, S_A, ac, 0, "grantRole(bytes32,address)", E(ROLE_B, C), UNAUTH,
             ARGS(A, ADMIN_B), "DEFAULT_ADMIN_ROLE cannot grant ROLE_B (admin is ADMIN_B)");
    call_ok(c, S_A, ac, 0, "grantRole(bytes32,address)", E(ADMIN_B, D), NULL,
            "grantRole(ADMIN_B, D) by the default admin");
    call_ok(c, S_D, ac, 0, "grantRole(bytes32,address)", E(ROLE_B, C), NULL,
            "grantRole(ROLE_B, C) by the ADMIN_B holder");
    call_rev(c, S_D, ac, 0, "grantRole(bytes32,address)", E(ROLE_A, C), UNAUTH,
             ARGS(D, ZERO), "the ADMIN_B holder cannot grant ROLE_A");

    if (call_ok(c, S_A, ac, 0, "revokeRole(bytes32,address)", E(ROLE_A, B), &r,
                "revokeRole(ROLE_A, B) by the admin")) {
        ck_log(c, &r, ac, "RoleRevoked(bytes32,address,address)", ARGS(ROLE_A, B, A),
               "revoke ROLE_A");
        evm_tx_result_free(&r);
    }
    call_rev(c, S_B, ac, 0, "useA()", E0(), UNAUTH, ARGS(B, ROLE_A),
             "useA after revoke refused");
    call_ok(c, S_C, ac, 0, "renounceRole(bytes32,address)", E(ROLE_B, C), NULL,
            "renounceRole(ROLE_B, C) by C itself");
    view(c, ac, "hasRole(bytes32,address)", E(ROLE_B, C), w, "hasRole");
    ck_u64(c, w, 0, "C no longer holds ROLE_B");
    view(c, ac, "counter()", E0(), w, "counter()");
    ck_u64(c, w, 1, "useA ran exactly once");

    /* raw slots (solc --storage-layout: slot 0 _roles; hasRole is the
     * struct's first member) */
    role_slot(key, ADMIN_B, D, 0);
    raw_slot(c, ac, key, w);
    ck_u64(c, w, 1, "raw slot hasRole[ADMIN_B][D32] = 1");
    role_slot(key, ZERO, A, 0);
    raw_slot(c, ac, key, w);
    ck_u64(c, w, 1, "raw slot hasRole[DEFAULT][A32] = 1");
    role_slot(key, ZERO, A_TWIN, 0);
    ck(c, !raw_slot(c, ac, key, w), "raw slot hasRole[DEFAULT][A_twin32]: no net write");
    mask20(w, A);
    role_slot(key, ZERO, w, 0);
    ck(c, !raw_slot(c, ac, key, w), "raw slot hasRole[DEFAULT][A_projection32]: no net write");
}

/* ── ReentrancyGuard + Pausable ────────────────────────────────────────── */

static void scen_guard(ctx_t *c)
{
    uint8_t g[32], x[32], w[32];
    buf_t hook, re;
    evm_tx_result_t r;

    if (deploy(c, S_A, K_GUARDED, E0(), 0, g, NULL, "deploy MockGuarded") != 0) return;
    if (deploy(c, S_A, K_ACTOR, E0(), 0, x, NULL, "deploy MockActor (attacker)") != 0) return;
    mk_hook(&hook);

    view(c, g, "paused()", E0(), w, "paused()");
    ck_u64(c, w, 0, "starts unpaused");
    call_rev(c, S_B, g, 0, "unpause()", E0(), "ExpectedPause()", NULL, 0,
             "unpause when not paused reverts");
    call_rev(c, S_B, g, 0, "pausedPing()", E0(), "ExpectedPause()", NULL, 0,
             "a whenPaused function reverts while not paused");

    enc_t e = E0();
    enc_word(&e, x);
    enc_bytes(&e, hook.b, hook.n);
    call_ok(c, S_B, g, 0, "guardedCall(address,bytes)", e, NULL, "guardedCall (plain)");

    /* same-function re-entry */
    e = E0();
    enc_word(&e, x);
    enc_bytes(&e, hook.b, hook.n);
    mk_call(&re, "guardedCall(address,bytes)", e);
    actor_mode(c, x, MODE_REENTER, g, &re);
    buf_free(&re);
    e = E0();
    enc_word(&e, x);
    enc_bytes(&e, hook.b, hook.n);
    call_ok(c, S_B, g, 0, "guardedCall(address,bytes)", e, NULL,
            "guardedCall with a same-function re-entry attempt completes");
    view(c, x, "reOk()", E0(), w, "reOk()");
    ck_u64(c, w, 0, "same-function re-entry refused");
    view(c, x, "reErr()", E0(), w, "reErr()");
    ck_sel(c, w, "ReentrantCall()", "same-function re-entry error = ReentrantCall()");

    /* cross-function re-entry */
    mk_call(&re, "guardedOther()", E0());
    actor_mode(c, x, MODE_REENTER, g, &re);
    buf_free(&re);
    e = E0();
    enc_word(&e, x);
    enc_bytes(&e, hook.b, hook.n);
    call_ok(c, S_B, g, 0, "guardedCall(address,bytes)", e, NULL,
            "guardedCall with a cross-function re-entry attempt completes");
    view(c, x, "reOk()", E0(), w, "reOk()");
    ck_u64(c, w, 0, "cross-function re-entry refused");
    view(c, x, "reErr()", E0(), w, "reErr()");
    ck_sel(c, w, "ReentrantCall()", "cross-function re-entry error = ReentrantCall()");
    view(c, x, "reAttempts()", E0(), w, "reAttempts()");
    ck_u64(c, w, 2, "the attacker tried twice");
    view(c, g, "counter()", E0(), w, "counter()");
    ck_u64(c, w, 3, "counter = 3 outer calls, no re-entered body ran");

    /* usable again after a revert */
    actor_mode(c, x, MODE_REVERT, NULL, NULL);
    e = E0();
    enc_word(&e, x);
    enc_bytes(&e, hook.b, hook.n);
    call_rev(c, S_B, g, 0, "guardedCall(address,bytes)", e, "GuardedCallFailed()", NULL, 0,
             "guardedCall whose callee reverts reverts");
    actor_mode(c, x, MODE_ACCEPT, NULL, NULL);
    e = E0();
    enc_word(&e, x);
    enc_bytes(&e, hook.b, hook.n);
    call_ok(c, S_B, g, 0, "guardedCall(address,bytes)", e, NULL,
            "guardedCall works again after the revert");
    call_ok(c, S_B, g, 0, "guardedOther()", E0(), NULL, "guardedOther works");
    view(c, g, "counter()", E0(), w, "counter()");
    ck_u64(c, w, 104, "counter = 4 + 100");

    /* pause */
    if (call_ok(c, S_C, g, 0, "pause()", E0(), &r, "pause")) {
        const evm_log_t *l = find_log(&r, g, "Paused(address)");
        ck(c, l && l->n_topics == 1 && l->data_len == 32, "Paused(account) logged");
        if (l && l->data_len == 32) ck_addr(c, l->data, C, "Paused data = the full 32-byte caller");
        evm_tx_result_free(&r);
    }
    call_rev(c, S_C, g, 0, "pause()", E0(), "EnforcedPause()", NULL, 0, "pause twice reverts");
    e = E0();
    enc_word(&e, x);
    enc_bytes(&e, hook.b, hook.n);
    call_rev(c, S_B, g, 0, "guardedCall(address,bytes)", e, "EnforcedPause()", NULL, 0,
             "a whenNotPaused function reverts while paused");
    call_ok(c, S_B, g, 0, "unguardedPing()", E0(), NULL, "an unmarked function works while paused");
    call_ok(c, S_B, g, 0, "pausedPing()", E0(), NULL, "a whenPaused function works while paused");
    call_ok(c, S_B, g, 0, "guardedOther()", E0(), NULL,
            "a nonReentrant function not marked whenNotPaused works while paused");
    if (call_ok(c, S_C, g, 0, "unpause()", E0(), &r, "unpause")) {
        ck(c, find_log(&r, g, "Unpaused(address)") != NULL, "Unpaused(account) logged");
        evm_tx_result_free(&r);
    }
    e = E0();
    enc_word(&e, x);
    enc_bytes(&e, hook.b, hook.n);
    call_ok(c, S_B, g, 0, "guardedCall(address,bytes)", e, NULL, "guardedCall after unpause");
    view(c, g, "counter()", E0(), w, "counter()");
    ck_u64(c, w, 205, "counter = 104 + 100 + 1");
    call_rev(c, S_B, g, 0, "pausedPing()", E0(), "ExpectedPause()", NULL, 0,
             "a whenPaused function reverts again after unpause");
    view(c, g, "pings()", E0(), w, "pings()");
    ck_u64(c, w, 1, "pings = 1");
    view(c, g, "pausedPings()", E0(), w, "pausedPings()");
    ck_u64(c, w, 1, "the whenPaused body ran exactly once (while paused)");

    /* solc --storage-layout: slot 0 _status (NOT_ENTERED = 1 after the calls) */
    raw_slot(c, g, U(0), w);
    ck_u64(c, w, 1, "raw guard status = NOT_ENTERED (1)");
    buf_free(&hook);
}

/* ── Timelock ──────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  target[32];
    uint64_t value;
    buf_t    data;
    uint8_t  salt[32];
    uint8_t  id[32];
} op_t;

/* id = keccak256(abi.encode(target, value, data, salt)) */
static void op_make(op_t *o, const uint8_t target[32], uint64_t value,
                    const uint8_t *data, size_t len, uint64_t salt)
{
    memset(o, 0, sizeof(*o));
    memcpy(o->target, target, 32);
    o->value = value;
    buf_put(&o->data, data, len);
    word_u64(o->salt, salt);
    o->salt[0] = 0x5a;                 /* a salt with a non-zero high byte */
    enc_t e = E0();
    enc_word(&e, o->target);
    enc_word(&e, U(value));
    enc_bytes(&e, data, len);
    enc_word(&e, o->salt);
    buf_t enc;
    memset(&enc, 0, sizeof(enc));
    enc_out(&e, &enc);
    kec(enc.b, enc.n, o->id);
    buf_free(&enc);
}

static void op_make_call(op_t *o, const uint8_t target[32], uint64_t value,
                         const char *sig, enc_t args, uint64_t salt)
{
    buf_t d;
    mk_call(&d, sig, args);
    op_make(o, target, value, d.b, d.n, salt);
    buf_free(&d);
}

static enc_t op_args(const op_t *o, int with_delay, uint64_t delay)
{
    enc_t e = E0();
    enc_word(&e, o->target);
    enc_word(&e, U(o->value));
    enc_bytes(&e, o->data.b, o->data.n);
    enc_word(&e, o->salt);
    if (with_delay) enc_word(&e, U(delay));
    return e;
}

static const char *SCHED = "schedule(address,uint256,bytes,bytes32,uint256)";
static const char *EXEC = "execute(address,uint256,bytes,bytes32)";
static const char *TL_STATE = "TimelockUnexpectedOperationState(bytes32,uint8)";
static const char *TL_FAILED = "TimelockCallFailed(bytes32,bytes)";
static const char *TL_TOO_LONG = "TimelockDelayTooLong(uint256,uint256)";
#define TL_MAX_DELAY 31536000ull          /* Timelock.MAX_DELAY = 365 days */

/* execute(o) by the executor B must revert TimelockCallFailed(o.id, reason)
 * with reason = inner_sig(iargs...) (NULL: empty reason) */
static void tl_exec_rev(ctx_t *c, const uint8_t tl[32], const op_t *o, const char *inner_sig,
                        const uint8_t *const *iargs, size_t ni, const char *what)
{
    call_rev_wrapped(c, S_B, tl, EXEC, op_args(o, 0, 0), TL_FAILED, o->id, inner_sig,
                     iargs, ni, what);
}

static int tl_schedule(ctx_t *c, int s, const uint8_t tl[32], const op_t *o,
                       uint64_t delay, const char *what)
{
    return call_ok(c, s, tl, 0, SCHED, op_args(o, 1, delay), NULL, what);
}

static int tl_execute(ctx_t *c, int s, const uint8_t tl[32], const op_t *o,
                      evm_tx_result_t *r, const char *what)
{
    return call_ok(c, s, tl, 0, EXEC, op_args(o, 0, 0), r, what);
}

static void tl_state(ctx_t *c, const uint8_t tl[32], const op_t *o, uint64_t want,
                     const char *what)
{
    uint8_t w[32];
    view(c, tl, "getOperationState(bytes32)", E(o->id), w, what);
    ck_u64(c, w, want, what);
}

/* schedule now with the delay, then move block time to the ready time */
static int tl_schedule_ready(ctx_t *c, const uint8_t tl[32], const op_t *o,
                             uint64_t delay, const char *what)
{
    int ok = tl_schedule(c, S_A, tl, o, delay, what);
    at_time(c, c->env.timestamp + delay);
    return ok;
}

static void scen_timelock(ctx_t *c)
{
    static const char *UNAUTH = "AccessControlUnauthorizedAccount(address,bytes32)";
    uint8_t tl[32], self[32], x[32], xr[32], xe[32], ft[32], w[32], key[32];
    evm_tx_result_t r;
    op_t o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14;
    const uint64_t MIN = 100;

    /* constructor refusals */
    {
        enc_t e = E0();
        enc_word(&e, U(MIN));
        enc_words(&e, NULL, 0);
        enc_words(&e, ARGS(B));
        enc_words(&e, ARGS(C));
        deploy_rev(c, S_A, K_TIMELOCK, e, "TimelockNoProposer()", NULL, 0,
                   "Timelock without a proposer refused");
        e = E0();
        enc_word(&e, U(MIN));
        enc_words(&e, ARGS(A));
        enc_words(&e, NULL, 0);
        enc_words(&e, ARGS(C));
        deploy_rev(c, S_A, K_TIMELOCK, e, "TimelockNoExecutor()", NULL, 0,
                   "Timelock without an executor refused");
        e = E0();
        enc_word(&e, U(MIN));
        enc_words(&e, ARGS(A, ZERO));
        enc_words(&e, ARGS(B));
        enc_words(&e, NULL, 0);
        deploy_rev(c, S_A, K_TIMELOCK, e, "TimelockInvalidAccount(address)", ARGS(ZERO),
                   "Timelock with a zero proposer refused");
        create_addr(self, A, c->nonce[S_A]);
        e = E0();
        enc_word(&e, U(MIN));
        enc_words(&e, ARGS(A));
        enc_words(&e, ARGS(B, self));
        enc_words(&e, NULL, 0);
        deploy_rev(c, S_A, K_TIMELOCK, e, "TimelockInvalidAccount(address)", ARGS(self),
                   "Timelock with itself as executor refused");
        e = E0();
        enc_word(&e, U(TL_MAX_DELAY + 1));
        enc_words(&e, ARGS(A));
        enc_words(&e, ARGS(B));
        enc_words(&e, NULL, 0);
        deploy_rev(c, S_A, K_TIMELOCK, e, TL_TOO_LONG, ARGS(U(TL_MAX_DELAY + 1), U(TL_MAX_DELAY)),
                   "Timelock with minDelay above MAX_DELAY refused");
    }

    enc_t e = E0();
    enc_word(&e, U(MIN));
    enc_words(&e, ARGS(A));
    enc_words(&e, ARGS(B));
    enc_words(&e, ARGS(C));
    if (deploy(c, S_A, K_TIMELOCK, e, 0, tl, &r, "deploy Timelock(100, [A], [B], [C])") != 0)
        return;
    ck_log(c, &r, tl, "RoleGranted(bytes32,address,address)", ARGS(PROPOSER, A, A),
           "constructor grants PROPOSER to A");
    evm_tx_result_free(&r);
    if (deploy(c, S_A, K_ACTOR, E0(), 0, x, NULL, "deploy MockActor (payee)") != 0) return;
    if (deploy(c, S_A, K_ACTOR, E0(), 0, xr, NULL, "deploy MockActor (reverting)") != 0) return;
    if (deploy(c, S_A, K_ACTOR, E0(), 0, xe, NULL, "deploy MockActor (re-entering)") != 0) return;
    if (deploy(c, S_A, K_FALSE, E0(), 0, ft, NULL, "deploy MockFalseTarget") != 0) return;

    view(c, tl, "hasRole(bytes32,address)", E(ZERO, tl), w, "hasRole");
    ck_u64(c, w, 1, "the timelock holds DEFAULT_ADMIN_ROLE");
    view(c, tl, "hasRole(bytes32,address)", E(ZERO, A), w, "hasRole");
    ck_u64(c, w, 0, "the deployer does not hold DEFAULT_ADMIN_ROLE");
    view(c, tl, "hasRole(bytes32,address)", E(PROPOSER, A_TWIN), w, "hasRole");
    ck_u64(c, w, 0, "the proposer's twin is not a proposer");
    view(c, tl, "getMinDelay()", E0(), w, "getMinDelay()");
    ck_u64(c, w, MIN, "getMinDelay() = 100");

    /* fund it (receive) */
    ok_tx(c, S_D, tl, 10 * Q, NULL, NULL, "send 10 q to the timelock");
    ck_u64v(c, bal(c, tl), 10 * Q, "timelock balance = 10 q");

    /* schedule rules */
    buf_t hook;
    mk_hook(&hook);
    op_make(&o1, x, Q, hook.b, hook.n, 1);
    view(c, tl, "hashOperation(address,uint256,bytes,bytes32)", op_args(&o1, 0, 0), w,
         "hashOperation");
    ck_word(c, w, o1.id, "hashOperation = keccak256(abi.encode(target, value, data, salt))");
    call_rev(c, S_B, tl, 0, SCHED, op_args(&o1, 1, MIN), UNAUTH, ARGS(B, PROPOSER),
             "schedule by a non-proposer refused");
    call_rev(c, S_A_TWIN, tl, 0, SCHED, op_args(&o1, 1, MIN), UNAUTH, ARGS(A_TWIN, PROPOSER),
             "schedule by the proposer's twin refused");
    call_rev(c, S_A, tl, 0, SCHED, op_args(&o1, 1, MIN - 1), "TimelockInsufficientDelay(uint256,uint256)",
             ARGS(U(MIN - 1), U(MIN)), "schedule with delay < minDelay refused");
    call_rev(c, S_A, tl, 0, SCHED, op_args(&o1, 1, TL_MAX_DELAY + 1), TL_TOO_LONG,
             ARGS(U(TL_MAX_DELAY + 1), U(TL_MAX_DELAY)), "schedule with delay > MAX_DELAY refused");
    view(c, tl, "MAX_DELAY()", E0(), w, "MAX_DELAY()");
    ck_u64(c, w, TL_MAX_DELAY, "MAX_DELAY() = 365 days");
    uint64_t t_sched = c->env.timestamp;
    if (call_ok(c, S_A, tl, 0, SCHED, op_args(&o1, 1, MIN), &r, "schedule o1")) {
        ck_word(c, r.output, o1.id, "schedule returns the operation id");
        ck_log(c, &r, tl, "CallScheduled(bytes32,address,uint256,bytes,bytes32,uint256)",
               ARGS(o1.id, x), "CallScheduled");
        evm_tx_result_free(&r);
    }
    tl_state(c, tl, &o1, 1, "o1 Pending");
    view(c, tl, "getReadyTime(bytes32)", E(o1.id), w, "getReadyTime");
    ck_u64(c, w, t_sched + MIN, "ready time = schedule time + delay");
    call_rev(c, S_A, tl, 0, SCHED, op_args(&o1, 1, MIN), TL_STATE, ARGS(o1.id, U(1)),
             "schedule of a pending id refused");

    /* execute rules */
    at_time(c, t_sched + MIN - 1);
    call_rev(c, S_B, tl, 0, EXEC, op_args(&o1, 0, 0), "TimelockNotReady(bytes32,uint256)",
             ARGS(o1.id, U(t_sched + MIN)), "execute at ready - 1 refused");
    at_time(c, t_sched + MIN);
    call_rev(c, S_A, tl, 0, EXEC, op_args(&o1, 0, 0), UNAUTH, ARGS(A, EXECUTOR),
             "execute by a non-executor refused");
    call_rev(c, S_B_TWIN, tl, 0, EXEC, op_args(&o1, 0, 0), UNAUTH, ARGS(B_TWIN, EXECUTOR),
             "execute by the executor's twin refused");
    op_make(&o2, x, Q, hook.b, hook.n, 2);
    call_rev(c, S_B, tl, 0, EXEC, op_args(&o2, 0, 0), TL_STATE, ARGS(o2.id, U(0)),
             "execute of an unscheduled id refused");
    if (tl_execute(c, S_B, tl, &o1, &r, "execute o1 at the ready time")) {
        ck_log(c, &r, tl, "CallExecuted(bytes32,address,uint256,bytes)", ARGS(o1.id, x),
               "CallExecuted");
        evm_tx_result_free(&r);
    }
    tl_state(c, tl, &o1, 2, "o1 Done");
    ck_u64v(c, bal(c, tl), 9 * Q, "the value left the timelock's balance (10 q - 1 q)");
    ck_u64v(c, bal(c, x), Q, "the target received 1 q");
    call_rev(c, S_B, tl, 0, EXEC, op_args(&o1, 0, 0), TL_STATE, ARGS(o1.id, U(2)),
             "double execute refused");
    call_rev(c, S_A, tl, 0, SCHED, op_args(&o1, 1, MIN), TL_STATE, ARGS(o1.id, U(2)),
             "schedule of a done id refused");

    /* cancel */
    op_make(&o3, x, Q, hook.b, hook.n, 3);
    tl_schedule_ready(c, tl, &o3, MIN, "schedule o3");
    call_rev(c, S_A, tl, 0, "cancel(bytes32)", E(o3.id), UNAUTH, ARGS(A, CANCELLER),
             "cancel by a non-canceller refused");
    call_rev(c, S_C, tl, 0, "cancel(bytes32)", E(o2.id), TL_STATE, ARGS(o2.id, U(0)),
             "cancel of an unscheduled id refused");
    if (call_ok(c, S_C, tl, 0, "cancel(bytes32)", E(o3.id), &r, "cancel o3")) {
        ck_log(c, &r, tl, "Cancelled(bytes32)", ARGS(o3.id), "Cancelled");
        evm_tx_result_free(&r);
    }
    tl_state(c, tl, &o3, 3, "o3 Cancelled");
    call_rev(c, S_B, tl, 0, EXEC, op_args(&o3, 0, 0), TL_STATE, ARGS(o3.id, U(3)),
             "execute after cancel refused (ready time reached)");
    call_rev(c, S_A, tl, 0, SCHED, op_args(&o3, 1, MIN), TL_STATE, ARGS(o3.id, U(3)),
             "schedule of a cancelled id refused");
    call_rev(c, S_C, tl, 0, "cancel(bytes32)", E(o3.id), TL_STATE, ARGS(o3.id, U(3)),
             "cancel twice refused");

    /* failed call: Pending and retryable */
    actor_mode(c, xr, MODE_REVERT, NULL, NULL);
    op_make(&o4, xr, Q, hook.b, hook.n, 4);
    tl_schedule_ready(c, tl, &o4, MIN, "schedule o4");
    tl_exec_rev(c, tl, &o4, "MockRejected()", NULL, 0,
                "execute whose call fails reverts (the target's MockRejected() carried as reason)");
    tl_state(c, tl, &o4, 1, "o4 still Pending after the failed call");
    ck_u64v(c, bal(c, tl), 9 * Q, "no value moved on the failed execute");
    actor_mode(c, xr, MODE_ACCEPT, NULL, NULL);
    tl_execute(c, S_B, tl, &o4, NULL, "retry of o4 succeeds");
    tl_state(c, tl, &o4, 2, "o4 Done after the retry");

    /* updateDelay: only through a delayed self-call */
    call_rev(c, S_A, tl, 0, "updateDelay(uint256)", E(U(50)), "TimelockUnauthorizedCaller(address)",
             ARGS(A), "direct updateDelay by the proposer refused");
    call_rev(c, S_B, tl, 0, "updateDelay(uint256)", E(U(50)), "TimelockUnauthorizedCaller(address)",
             ARGS(B), "direct updateDelay by the executor refused");
    op_make_call(&o5, tl, 0, "updateDelay(uint256)", E(U(50)), 5);
    tl_schedule_ready(c, tl, &o5, MIN, "schedule updateDelay(50)");
    if (tl_execute(c, S_B, tl, &o5, &r, "execute updateDelay(50)")) {
        ck(c, find_log(&r, tl, "MinDelayChange(uint256,uint256)") != NULL, "MinDelayChange logged");
        evm_tx_result_free(&r);
    }
    view(c, tl, "getMinDelay()", E0(), w, "getMinDelay()");
    ck_u64(c, w, 50, "minDelay = 50 after the delayed update");
    {
        op_t ox;
        op_make_call(&ox, tl, 0, "updateDelay(uint256)", E(U(TL_MAX_DELAY + 1)), 105);
        tl_schedule_ready(c, tl, &ox, 50, "schedule updateDelay(MAX_DELAY + 1)");
        tl_exec_rev(c, tl, &ox, TL_TOO_LONG, ARGS(U(TL_MAX_DELAY + 1), U(TL_MAX_DELAY)),
                    "a delayed updateDelay above MAX_DELAY fails");
        view(c, tl, "getMinDelay()", E0(), w, "getMinDelay()");
        ck_u64(c, w, 50, "minDelay still 50 after the refused update");
        buf_free(&ox.data);
    }

    /* role change through a delayed self-call. The grant to D runs BEFORE the
     * revoke of A: A is the only proposer until then, and the revoke of the
     * last proposer is refused (tested below). */
    op_make_call(&o6, tl, 0, "revokeRole(bytes32,address)", E(PROPOSER, A), 6);
    op_make_call(&o7, tl, 0, "grantRole(bytes32,address)", E(PROPOSER, D), 7);
    tl_schedule(c, S_A, tl, &o6, 50, "schedule revokeRole(PROPOSER, A)");
    tl_schedule_ready(c, tl, &o7, 50, "schedule grantRole(PROPOSER, D)");
    if (tl_execute(c, S_B, tl, &o7, &r, "execute grantRole(PROPOSER, D)")) {
        ck_log(c, &r, tl, "RoleGranted(bytes32,address,address)", ARGS(PROPOSER, D, tl),
               "delayed grant (sender = the timelock)");
        evm_tx_result_free(&r);
    }
    tl_execute(c, S_B, tl, &o6, NULL, "execute revokeRole(PROPOSER, A) (D still a proposer)");
    op_make(&o8, x, 0, hook.b, hook.n, 8);
    call_rev(c, S_A, tl, 0, SCHED, op_args(&o8, 1, 50), UNAUTH, ARGS(A, PROPOSER),
             "the former proposer cannot schedule");
    call_rev(c, S_A, tl, 0, "grantRole(bytes32,address)", E(PROPOSER, A), UNAUTH,
             ARGS(A, ZERO), "a direct grantRole by the former proposer fails");
    call_rev(c, S_D, tl, 0, "grantRole(bytes32,address)", E(PROPOSER, B), UNAUTH,
             ARGS(D, ZERO), "a direct grantRole by the new proposer fails");
    tl_schedule(c, S_D, tl, &o8, 50, "the new proposer schedules");

    /* DEFAULT_ADMIN_ROLE stays with the timelock alone */
    op_make_call(&o9, tl, 0, "grantRole(bytes32,address)", E(ZERO, D), 9);
    op_make_call(&o10, tl, 0, "renounceRole(bytes32,address)", E(ZERO, tl), 10);
    call_ok(c, S_D, tl, 0, SCHED, op_args(&o9, 1, 50), NULL, "schedule grantRole(DEFAULT, D)");
    call_ok(c, S_D, tl, 0, SCHED, op_args(&o10, 1, 50), NULL, "schedule renounceRole(DEFAULT, tl)");
    at_time(c, c->env.timestamp + 50);
    tl_exec_rev(c, tl, &o9, "TimelockAdminFixed()", NULL, 0,
                "a delayed grant of DEFAULT_ADMIN_ROLE to an account fails (TimelockAdminFixed)");
    tl_exec_rev(c, tl, &o10, "TimelockRenounceDisabled()", NULL, 0,
                "a delayed renounce of the timelock's DEFAULT_ADMIN_ROLE fails "
                "(TimelockRenounceDisabled)");
    {
        op_t oa;
        op_make_call(&oa, tl, 0, "revokeRole(bytes32,address)", E(ZERO, tl), 109);
        call_ok(c, S_D, tl, 0, SCHED, op_args(&oa, 1, 50), NULL,
                "schedule revokeRole(DEFAULT, tl)");
        at_time(c, c->env.timestamp + 50);
        tl_exec_rev(c, tl, &oa, "TimelockAdminFixed()", NULL, 0,
                    "a delayed revoke of the timelock's DEFAULT_ADMIN_ROLE fails (TimelockAdminFixed)");
        buf_free(&oa.data);
    }
    view(c, tl, "hasRole(bytes32,address)", E(ZERO, D), w, "hasRole");
    ck_u64(c, w, 0, "D did not get DEFAULT_ADMIN_ROLE");
    view(c, tl, "hasRole(bytes32,address)", E(ZERO, tl), w, "hasRole");
    ck_u64(c, w, 1, "the timelock still holds DEFAULT_ADMIN_ROLE");

    /* renounceRole reverts for every role, holder or not */
    call_rev(c, S_D, tl, 0, "renounceRole(bytes32,address)", E(PROPOSER, D),
             "TimelockRenounceDisabled()", NULL, 0, "renounceRole(PROPOSER) by a proposer refused");
    call_rev(c, S_B, tl, 0, "renounceRole(bytes32,address)", E(EXECUTOR, B),
             "TimelockRenounceDisabled()", NULL, 0, "renounceRole(EXECUTOR) by the executor refused");
    call_rev(c, S_C, tl, 0, "renounceRole(bytes32,address)", E(CANCELLER, C),
             "TimelockRenounceDisabled()", NULL, 0, "renounceRole(CANCELLER) by the canceller refused");
    call_rev(c, S_A, tl, 0, "renounceRole(bytes32,address)", E(ZERO, A),
             "TimelockRenounceDisabled()", NULL, 0, "renounceRole(DEFAULT_ADMIN_ROLE) refused");
    view(c, tl, "hasRole(bytes32,address)", E(PROPOSER, D), w, "hasRole");
    ck_u64(c, w, 1, "D still a proposer after the refused renounce");
    view(c, tl, "hasRole(bytes32,address)", E(EXECUTOR, B), w, "hasRole");
    ck_u64(c, w, 1, "B still an executor after the refused renounce");
    view(c, tl, "hasRole(bytes32,address)", E(CANCELLER, C), w, "hasRole");
    ck_u64(c, w, 1, "C still a canceller after the refused renounce");

    /* delayed grants to address(0) / the timelock, revokes of the last holder.
     * Here D is the only proposer and B the only executor. */
    {
        op_t og0, ogs, ole, olp, onh;
        op_make_call(&og0, tl, 0, "grantRole(bytes32,address)", E(EXECUTOR, ZERO), 110);
        op_make_call(&ogs, tl, 0, "grantRole(bytes32,address)", E(EXECUTOR, tl), 111);
        op_make_call(&ole, tl, 0, "revokeRole(bytes32,address)", E(EXECUTOR, B), 112);
        op_make_call(&olp, tl, 0, "revokeRole(bytes32,address)", E(PROPOSER, D), 113);
        op_make_call(&onh, tl, 0, "revokeRole(bytes32,address)", E(EXECUTOR, C), 114);
        call_ok(c, S_D, tl, 0, SCHED, op_args(&og0, 1, 50), NULL, "schedule grantRole(EXECUTOR, 0)");
        call_ok(c, S_D, tl, 0, SCHED, op_args(&ogs, 1, 50), NULL, "schedule grantRole(EXECUTOR, tl)");
        call_ok(c, S_D, tl, 0, SCHED, op_args(&ole, 1, 50), NULL, "schedule revokeRole(EXECUTOR, B)");
        call_ok(c, S_D, tl, 0, SCHED, op_args(&olp, 1, 50), NULL, "schedule revokeRole(PROPOSER, D)");
        call_ok(c, S_D, tl, 0, SCHED, op_args(&onh, 1, 50), NULL, "schedule revokeRole(EXECUTOR, C)");
        at_time(c, c->env.timestamp + 50);
        tl_exec_rev(c, tl, &og0, "TimelockInvalidAccount(address)", ARGS(ZERO),
                    "a delayed grantRole to address(0) fails");
        tl_exec_rev(c, tl, &ogs, "TimelockInvalidAccount(address)", ARGS(tl),
                    "a delayed grantRole to the timelock itself fails");
        tl_exec_rev(c, tl, &ole, "TimelockLastHolder(bytes32)", ARGS(EXECUTOR),
                    "a delayed revoke of the last executor fails");
        tl_exec_rev(c, tl, &olp, "TimelockLastHolder(bytes32)", ARGS(PROPOSER),
                    "a delayed revoke of the last proposer fails");
        tl_execute(c, S_B, tl, &onh, NULL,
                   "a delayed revoke of a non-holder while one executor is left is a no-op");
        view(c, tl, "hasRole(bytes32,address)", E(EXECUTOR, B), w, "hasRole");
        ck_u64(c, w, 1, "B still the executor");
        view(c, tl, "hasRole(bytes32,address)", E(PROPOSER, D), w, "hasRole");
        ck_u64(c, w, 1, "D still the proposer");
        view(c, tl, "hasRole(bytes32,address)", E(EXECUTOR, ZERO), w, "hasRole");
        ck_u64(c, w, 0, "address(0) is not an executor");
        view(c, tl, "hasRole(bytes32,address)", E(EXECUTOR, tl), w, "hasRole");
        ck_u64(c, w, 0, "the timelock is not an executor");
        op_t *tmp[] = { &og0, &ogs, &ole, &olp, &onh };
        for (size_t i = 0; i < sizeof(tmp) / sizeof(tmp[0]); i++) buf_free(&tmp[i]->data);
    }

    /* re-entry into execute from the call */
    op_make(&o11, xe, 0, hook.b, hook.n, 11);
    {
        buf_t re;
        mk_call(&re, EXEC, op_args(&o11, 0, 0));
        actor_mode(c, xe, MODE_REENTER, tl, &re);
        buf_free(&re);
    }
    call_ok(c, S_D, tl, 0, SCHED, op_args(&o11, 1, 50), NULL, "schedule o11 (re-entering target)");
    at_time(c, c->env.timestamp + 50);
    tl_execute(c, S_B, tl, &o11, NULL, "execute o11 completes");
    view(c, xe, "reErr()", E0(), w, "reErr()");
    ck_sel(c, w, "ReentrantCall()", "re-entry into execute refused with ReentrantCall()");
    tl_state(c, tl, &o11, 2, "o11 Done once");

    /* CALL success = execution success */
    op_make_call(&o12, ft, 0, "check()", E0(), 12);
    call_ok(c, S_D, tl, 0, SCHED, op_args(&o12, 1, 50), NULL, "schedule o12 (target returns false)");
    at_time(c, c->env.timestamp + 50);
    tl_execute(c, S_B, tl, &o12, NULL, "execute of a target returning false completes");
    tl_state(c, tl, &o12, 2, "o12 Done");
    view(c, ft, "calls()", E0(), w, "calls()");
    ck_u64(c, w, 1, "the false-returning target ran once");

    /* ticket exit */
    uint64_t before = bal(c, tl);
    op_make(&o13, TICKET, 2 * Q, FP, 64, 13);
    op_make(&o14, TICKET, 2 * Q, FP, 63, 14);
    call_ok(c, S_D, tl, 0, SCHED, op_args(&o13, 1, 50), NULL, "schedule ticket (64-byte fp)");
    call_ok(c, S_D, tl, 0, SCHED, op_args(&o14, 1, 50), NULL, "schedule ticket (63-byte fp)");
    at_time(c, c->env.timestamp + 50);
    tl_exec_rev(c, tl, &o14, NULL, NULL, 0,
                "execute to the ticket address with 63 bytes of calldata reverts (empty reason)");
    ck_u64v(c, bal(c, tl), before, "no balance moved (63 bytes)");
    if (tl_execute(c, S_B, tl, &o13, &r, "execute to the ticket address (64 bytes, 2 q)")) {
        ck_ticket(c, &r, 2 * Q, FP, "timelock ticket");
        evm_tx_result_free(&r);
    }
    ck_u64v(c, bal(c, tl), before - 2 * Q, "the timelock's balance dropped by the ticket");
    {
        op_t o15;
        op_make(&o15, TICKET, Q + 1, FP, 64, 15);
        call_ok(c, S_D, tl, 0, SCHED, op_args(&o15, 1, 50), NULL, "schedule ticket (non-q value)");
        at_time(c, c->env.timestamp + 50);
        tl_exec_rev(c, tl, &o15, NULL, NULL, 0,
                    "execute to the ticket address with a non-q value reverts (empty reason)");
        ck_u64v(c, bal(c, tl), before - 2 * Q, "no balance moved (non-q value)");
        buf_free(&o15.data);
    }

    /* raw slots (solc --storage-layout: slot 0 _roles) */
    role_slot(key, PROPOSER, D, 0);
    raw_slot(c, tl, key, w);
    ck_u64(c, w, 1, "raw slot hasRole[PROPOSER][D32] = 1");
    role_slot(key, PROPOSER, A_TWIN, 0);
    ck(c, !raw_slot(c, tl, key, w), "raw slot hasRole[PROPOSER][A_twin32]: no net write");

    buf_free(&hook);
    op_t *all[] = { &o1, &o2, &o3, &o4, &o5, &o6, &o7, &o8, &o9, &o10, &o11, &o12, &o13, &o14 };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) buf_free(&all[i]->data);
}

/* ── MultisigVault ─────────────────────────────────────────────────────── */

static const char *SUBMIT = "submit(address,uint256,bytes)";

/* submit by s; @return the id (UINT64_MAX on failure) */
static uint64_t v_submit(ctx_t *c, int s, const uint8_t v[32], const uint8_t to[32],
                         uint64_t value, const buf_t *data, const char *what)
{
    evm_tx_result_t r;
    enc_t e = E0();
    enc_word(&e, to);
    enc_word(&e, U(value));
    enc_bytes(&e, data->b, data->n);
    if (!call_ok(c, s, v, 0, SUBMIT, e, &r, what)) return UINT64_MAX;
    uint64_t id = 0;
    for (int i = 24; i < 32; i++) id = (id << 8) | r.output[i];
    evm_tx_result_free(&r);
    return id;
}

static uint64_t v_submit_call(ctx_t *c, int s, const uint8_t v[32], const uint8_t to[32],
                              const char *sig, enc_t args, const char *what)
{
    buf_t d;
    mk_call(&d, sig, args);
    uint64_t id = v_submit(c, s, v, to, 0, &d, what);
    buf_free(&d);
    return id;
}

/* execute(id) by s must revert VaultCallFailed(id, reason) with
 * reason = inner_sig(iargs...) (NULL: empty reason) */
static void v_exec_rev(ctx_t *c, int s, const uint8_t v[32], uint64_t id, const char *inner_sig,
                       const uint8_t *const *iargs, size_t ni, const char *what)
{
    uint8_t idw[32];
    word_u64(idw, id);
    call_rev_wrapped(c, s, v, "execute(uint256)", E(idw), "VaultCallFailed(uint256,bytes)", idw,
                     inner_sig, iargs, ni, what);
}

static void scen_vault(ctx_t *c)
{
    static const char *NOT_OWNER = "VaultNotOwner(address)";
    static const char *CFG = "VaultInvalidConfig(uint256,uint256)";
    uint8_t v[32], self[32], x[32], xr[32], xe[32], ft[32], w[32], key[32];
    evm_tx_result_t r;
    buf_t hook;

    /* constructor refusals */
    {
        enc_t e = E0();
        enc_words(&e, ARGS(A, ZERO, C));
        enc_word(&e, U(2));
        deploy_rev(c, S_A, K_VAULT, e, "VaultInvalidOwner(address)", ARGS(ZERO),
                   "vault with a zero owner refused");
        e = E0();
        enc_words(&e, ARGS(A, B, A));
        enc_word(&e, U(2));
        deploy_rev(c, S_A, K_VAULT, e, "VaultInvalidOwner(address)", ARGS(A),
                   "vault with a duplicate owner refused");
        e = E0();
        enc_words(&e, ARGS(A, A_TWIN));
        enc_word(&e, U(2));
        deploy(c, S_A, K_VAULT, e, 0, w, NULL, "an owner and its twin are distinct owners");
        e = E0();
        enc_words(&e, ARGS(A, B, C));
        enc_word(&e, U(0));
        deploy_rev(c, S_A, K_VAULT, e, CFG, ARGS(U(3), U(0)), "threshold 0 refused");
        e = E0();
        enc_words(&e, ARGS(A, B, C));
        enc_word(&e, U(4));
        deploy_rev(c, S_A, K_VAULT, e, CFG, ARGS(U(3), U(4)), "threshold > owner count refused");
        create_addr(self, A, c->nonce[S_A]);
        e = E0();
        enc_words(&e, ARGS(A, self));
        enc_word(&e, U(1));
        deploy_rev(c, S_A, K_VAULT, e, "VaultInvalidOwner(address)", ARGS(self),
                   "vault with itself as owner refused");

        uint8_t many[33][32];
        const uint8_t *pm[33];
        for (int i = 0; i < 33; i++) {
            mk_addr(many[i], (uint8_t)(0xd0 + (i >> 4)), (uint8_t)(0x60 + i));
            pm[i] = many[i];
        }
        e = E0();
        enc_words(&e, pm, 33);
        enc_word(&e, U(1));
        deploy_rev(c, S_A, K_VAULT, e, CFG, ARGS(U(33), U(1)), "33 owners refused");
        e = E0();
        enc_words(&e, pm, 32);
        enc_word(&e, U(32));
        deploy(c, S_A, K_VAULT, e, 0, w, NULL, "32 owners, threshold 32 accepted");

        /* addOwner at 32 owners: 31 others + A at threshold 1, so A alone
         * passes the proposal and the refusal comes from the 32-owner cap */
        uint8_t vf[32];
        pm[31] = A;
        e = E0();
        enc_words(&e, pm, 32);
        enc_word(&e, U(1));
        if (deploy(c, S_A, K_VAULT, e, 0, vf, NULL, "32 owners incl. A, threshold 1") == 0) {
            uint64_t pf = v_submit_call(c, S_A, vf, vf, "addOwner(address)", E(D),
                                        "submit addOwner(D) at 32 owners");
            v_exec_rev(c, S_A, vf, pf, CFG, ARGS(U(33), U(1)),
                       "addOwner at 32 owners fails (VaultInvalidConfig(33, 1))");
            view(c, vf, "isOwner(address)", E(D), w, "isOwner(D)");
            ck_u64(c, w, 0, "D did not become the 33rd owner");
        }
    }

    enc_t e = E0();
    enc_words(&e, ARGS(A, B, C));
    enc_word(&e, U(2));
    if (deploy(c, S_A, K_VAULT, e, 0, v, NULL, "deploy MultisigVault([A, B, C], 2)") != 0) return;
    if (deploy(c, S_A, K_ACTOR, E0(), 0, x, NULL, "deploy MockActor (payee)") != 0) return;
    if (deploy(c, S_A, K_ACTOR, E0(), 0, xr, NULL, "deploy MockActor (reverting)") != 0) return;
    if (deploy(c, S_A, K_ACTOR, E0(), 0, xe, NULL, "deploy MockActor (re-entering)") != 0) return;
    if (deploy(c, S_A, K_FALSE, E0(), 0, ft, NULL, "deploy MockFalseTarget") != 0) return;
    mk_hook(&hook);
    if (ok_tx(c, S_D, v, 20 * Q, NULL, &r, "send 20 q to the vault")) {
        ck_log(c, &r, v, "Deposit(address,uint256)", ARGS(D), "Deposit");
        evm_tx_result_free(&r);
    }

    /* submit / approve / execute */
    {
        enc_t s = E0();
        enc_word(&s, x);
        enc_word(&s, U(Q));
        enc_bytes(&s, hook.b, hook.n);
        call_rev(c, S_D, v, 0, SUBMIT, s, NOT_OWNER, ARGS(D), "submit by a non-owner refused");
        s = E0();
        enc_word(&s, x);
        enc_word(&s, U(Q));
        enc_bytes(&s, hook.b, hook.n);
        call_rev(c, S_A_TWIN, v, 0, SUBMIT, s, NOT_OWNER, ARGS(A_TWIN),
                 "submit by an owner's twin refused");
    }
    uint64_t p0 = v_submit(c, S_A, v, x, Q, &hook, "submit p0 (1 q to the payee)");
    ck_u64v(c, p0, 0, "ids start at 0");
    call_rev(c, S_A, v, 0, "approve(uint256)", E(U(p0)), "VaultAlreadyApproved(uint256,address)",
             ARGS(U(p0), A), "double approval refused (the submit counted)");
    call_rev(c, S_D, v, 0, "approve(uint256)", E(U(p0)), NOT_OWNER, ARGS(D),
             "approve by a non-owner refused");
    call_rev(c, S_A, v, 0, "execute(uint256)", E(U(p0)), "VaultBelowThreshold(uint256,uint256,uint256)",
             ARGS(U(p0), U(1), U(2)), "execute below threshold refused");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p0)), NULL, "approve p0 by B");
    call_ok(c, S_B, v, 0, "revokeApproval(uint256)", E(U(p0)), NULL, "revoke p0 by B");
    call_rev(c, S_B, v, 0, "revokeApproval(uint256)", E(U(p0)), "VaultNotApproved(uint256,address)",
             ARGS(U(p0), B), "revoke without approval refused");
    call_rev(c, S_C, v, 0, "execute(uint256)", E(U(p0)), "VaultBelowThreshold(uint256,uint256,uint256)",
             ARGS(U(p0), U(1), U(2)), "revoke then execute below threshold refused");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p0)), NULL, "approve p0 by B again");
    view(c, v, "isApproved(uint256,address)", E(U(p0), B_TWIN), w, "isApproved");
    ck_u64(c, w, 0, "B's twin has not approved");
    if (call_ok(c, S_C, v, 0, "execute(uint256)", E(U(p0)), &r, "execute p0 by C (any owner)")) {
        ck_log(c, &r, v, "Executed(uint256)", ARGS(U(p0)), "Executed");
        evm_tx_result_free(&r);
    }
    ck_u64v(c, bal(c, v), 19 * Q, "vault balance 20 q - 1 q");
    ck_u64v(c, bal(c, x), Q, "payee received 1 q");
    call_rev(c, S_C, v, 0, "execute(uint256)", E(U(p0)), "VaultAlreadyExecuted(uint256)",
             ARGS(U(p0)), "double execute refused");
    call_rev(c, S_C, v, 0, "approve(uint256)", E(U(p0)), "VaultAlreadyExecuted(uint256)",
             ARGS(U(p0)), "approve of an executed proposal refused");
    call_rev(c, S_C, v, 0, "execute(uint256)", E(U(99)), "VaultUnknownProposal(uint256)",
             ARGS(U(99)), "execute of a nonexistent id refused");
    call_rev(c, S_C, v, 0, "approve(uint256)", E(U(99)), "VaultUnknownProposal(uint256)",
             ARGS(U(99)), "approve of a nonexistent id refused");

    /* configuration changes only as a passed proposal */
    call_rev(c, S_A, v, 0, "addOwner(address)", E(D), "VaultNotSelf(address)", ARGS(A),
             "direct addOwner refused");
    call_rev(c, S_A, v, 0, "removeOwner(address)", E(C), "VaultNotSelf(address)", ARGS(A),
             "direct removeOwner refused");
    call_rev(c, S_A, v, 0, "changeThreshold(uint256)", E(U(1)), "VaultNotSelf(address)", ARGS(A),
             "direct changeThreshold refused");

    /* failed call retryable */
    actor_mode(c, xr, MODE_REVERT, NULL, NULL);
    uint64_t p1 = v_submit(c, S_A, v, xr, Q, &hook, "submit p1 (reverting target)");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p1)), NULL, "approve p1");
    v_exec_rev(c, S_C, v, p1, "MockRejected()", NULL, 0,
               "execute whose call fails reverts (the target's MockRejected() carried as reason)");
    ck_u64v(c, bal(c, v), 19 * Q, "no value moved on the failed execute");
    actor_mode(c, xr, MODE_ACCEPT, NULL, NULL);
    call_ok(c, S_C, v, 0, "execute(uint256)", E(U(p1)), NULL, "retry of p1 succeeds");
    ck_u64v(c, bal(c, v), 18 * Q, "vault balance 18 q");

    /* config version voids older proposals */
    uint64_t p2 = v_submit(c, S_A, v, x, Q, &hook, "submit p2");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p2)), NULL, "approve p2 (ready)");
    uint64_t p3 = v_submit_call(c, S_A, v, v, "addOwner(address)", E(D), "submit addOwner(D)");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p3)), NULL, "approve addOwner(D)");
    if (call_ok(c, S_C, v, 0, "execute(uint256)", E(U(p3)), &r, "execute addOwner(D)")) {
        ck_log(c, &r, v, "OwnerAdded(address)", ARGS(D), "OwnerAdded");
        evm_tx_result_free(&r);
    }
    view(c, v, "configVersion()", E0(), w, "configVersion()");
    ck_u64(c, w, 1, "configVersion = 1");
    call_rev(c, S_C, v, 0, "execute(uint256)", E(U(p2)), "VaultStaleProposal(uint256,uint256,uint256)",
             ARGS(U(p2), U(0), U(1)), "a proposal of an older version cannot execute");
    call_rev(c, S_C, v, 0, "approve(uint256)", E(U(p2)), "VaultStaleProposal(uint256,uint256,uint256)",
             ARGS(U(p2), U(0), U(1)), "a proposal of an older version cannot be approved");

    /* remove -> re-add does not revive approvals */
    uint64_t p4 = v_submit(c, S_D, v, x, Q, &hook, "submit p4 by D");
    call_ok(c, S_C, v, 0, "approve(uint256)", E(U(p4)), NULL, "approve p4 by C (ready)");
    uint64_t p5 = v_submit_call(c, S_A, v, v, "removeOwner(address)", E(D), "submit removeOwner(D)");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p5)), NULL, "approve removeOwner(D)");
    call_ok(c, S_C, v, 0, "execute(uint256)", E(U(p5)), NULL, "execute removeOwner(D)");
    view(c, v, "isOwner(address)", E(D), w, "isOwner(D)");
    ck_u64(c, w, 0, "D is no longer an owner");
    uint64_t p6 = v_submit_call(c, S_A, v, v, "addOwner(address)", E(D), "submit addOwner(D) again");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p6)), NULL, "approve re-add");
    call_ok(c, S_C, v, 0, "execute(uint256)", E(U(p6)), NULL, "execute re-add D");
    call_rev(c, S_C, v, 0, "execute(uint256)", E(U(p4)), "VaultStaleProposal(uint256,uint256,uint256)",
             ARGS(U(p4), U(1), U(3)), "remove -> re-add does not revive p4's approvals");

    /* changes that break the invariant fail */
    uint64_t p7 = v_submit_call(c, S_A, v, v, "changeThreshold(uint256)", E(U(5)),
                                "submit changeThreshold(5) with 4 owners");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p7)), NULL, "approve p7");
    v_exec_rev(c, S_C, v, p7, CFG, ARGS(U(4), U(5)), "threshold > owner count fails");
    uint64_t p8 = v_submit_call(c, S_A, v, v, "changeThreshold(uint256)", E(U(0)),
                                "submit changeThreshold(0)");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p8)), NULL, "approve p8");
    v_exec_rev(c, S_C, v, p8, CFG, ARGS(U(4), U(0)), "threshold 0 fails");
    uint64_t p9 = v_submit_call(c, S_A, v, v, "addOwner(address)", E(v), "submit addOwner(vault)");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p9)), NULL, "approve p9");
    v_exec_rev(c, S_C, v, p9, "VaultInvalidOwner(address)", ARGS(v),
               "adding the vault itself as owner fails");
    uint64_t p10 = v_submit_call(c, S_A, v, v, "changeThreshold(uint256)", E(U(4)),
                                 "submit changeThreshold(4)");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p10)), NULL, "approve p10");
    call_ok(c, S_C, v, 0, "execute(uint256)", E(U(p10)), NULL, "threshold = owner count (4) accepted");
    uint64_t p11 = v_submit_call(c, S_A, v, v, "removeOwner(address)", E(D),
                                 "submit removeOwner(D) at threshold 4");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p11)), NULL, "approve p11 B");
    call_ok(c, S_C, v, 0, "approve(uint256)", E(U(p11)), NULL, "approve p11 C");
    call_ok(c, S_D, v, 0, "approve(uint256)", E(U(p11)), NULL, "approve p11 D");
    v_exec_rev(c, S_D, v, p11, CFG, ARGS(U(3), U(4)),
               "a removal that breaks threshold <= owner count fails");
    view(c, v, "isOwner(address)", E(D), w, "isOwner(D)");
    ck_u64(c, w, 1, "D still an owner after the refused removal");
    uint64_t p12 = v_submit_call(c, S_A, v, v, "changeThreshold(uint256)", E(U(2)),
                                 "submit changeThreshold(2)");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p12)), NULL, "approve p12 B");
    call_ok(c, S_C, v, 0, "approve(uint256)", E(U(p12)), NULL, "approve p12 C");
    call_ok(c, S_D, v, 0, "approve(uint256)", E(U(p12)), NULL, "approve p12 D");
    call_ok(c, S_D, v, 0, "execute(uint256)", E(U(p12)), NULL, "threshold back to 2");
    view(c, v, "threshold()", E0(), w, "threshold()");
    ck_u64(c, w, 2, "threshold = 2");

    /* re-entry into execute from the call */
    {
        buf_t re;
        uint64_t next;
        view(c, v, "proposalCount()", E0(), w, "proposalCount()");
        next = 0;
        for (int i = 24; i < 32; i++) next = (next << 8) | w[i];
        mk_call(&re, "execute(uint256)", E(U(next)));
        actor_mode(c, xe, MODE_REENTER, v, &re);
        buf_free(&re);
        uint64_t p13 = v_submit(c, S_A, v, xe, 0, &hook, "submit p13 (re-entering target)");
        ck_u64v(c, p13, next, "p13 got the predicted id");
        call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p13)), NULL, "approve p13");
        call_ok(c, S_C, v, 0, "execute(uint256)", E(U(p13)), NULL, "execute p13 completes");
        view(c, xe, "reErr()", E0(), w, "reErr()");
        ck_sel(c, w, "ReentrantCall()", "re-entry into vault execute refused with ReentrantCall()");
    }

    /* CALL success = execution success */
    uint64_t p14 = v_submit_call(c, S_A, v, ft, "check()", E0(), "submit p14 (target returns false)");
    call_ok(c, S_B, v, 0, "approve(uint256)", E(U(p14)), NULL, "approve p14");
    call_ok(c, S_C, v, 0, "execute(uint256)", E(U(p14)), NULL,
            "execute of a target returning false completes");
    view_at(c, v, "getProposal(uint256)", E(U(p14)), 5, w, "getProposal(p14).executed");
    ck_u64(c, w, 1, "p14 executed");
    view(c, ft, "calls()", E0(), w, "calls()");
    ck_u64(c, w, 1, "the false-returning target ran once");

    /* ticket exit */
    {
        buf_t fp64, fp63;
        memset(&fp64, 0, sizeof(fp64));
        memset(&fp63, 0, sizeof(fp63));
        buf_put(&fp64, FP, 64);
        buf_put(&fp63, FP, 63);
        uint64_t before = bal(c, v);
        uint64_t t63 = v_submit(c, S_A, v, TICKET, 3 * Q, &fp63, "submit ticket (63 bytes)");
        call_ok(c, S_B, v, 0, "approve(uint256)", E(U(t63)), NULL, "approve");
        v_exec_rev(c, S_C, v, t63, NULL, NULL, 0,
                   "vault execute to the ticket address with 63 bytes reverts (empty reason)");
        uint64_t tnq = v_submit(c, S_A, v, TICKET, 3 * Q + 1, &fp64, "submit ticket (non-q value)");
        call_ok(c, S_B, v, 0, "approve(uint256)", E(U(tnq)), NULL, "approve");
        v_exec_rev(c, S_C, v, tnq, NULL, NULL, 0,
                   "vault execute to the ticket address with a non-q value reverts (empty reason)");
        ck_u64v(c, bal(c, v), before, "no balance moved by the refused tickets");
        uint64_t tok = v_submit(c, S_A, v, TICKET, 3 * Q, &fp64, "submit ticket (64 bytes, 3 q)");
        call_ok(c, S_B, v, 0, "approve(uint256)", E(U(tok)), NULL, "approve");
        if (call_ok(c, S_C, v, 0, "execute(uint256)", E(U(tok)), &r,
                    "vault execute to the ticket address")) {
            ck_ticket(c, &r, 3 * Q, FP, "vault ticket");
            evm_tx_result_free(&r);
        }
        ck_u64v(c, bal(c, v), before - 3 * Q, "the vault's balance dropped by the ticket");
        buf_free(&fp64);
        buf_free(&fp63);
    }

    /* raw slots (solc --storage-layout: slot 2 _isOwner, slot 7 _approved) */
    slot_map(key, A, U(2));
    raw_slot(c, v, key, w);
    ck_u64(c, w, 1, "raw slot _isOwner[A32] = 1");
    slot_map(key, A_TWIN, U(2));
    ck(c, !raw_slot(c, v, key, w), "raw slot _isOwner[A_twin32]: no net write");
    {
        uint8_t inner[32];
        slot_map(inner, U(p0), U(7));
        slot_map(key, B, inner);
        raw_slot(c, v, key, w);
        ck_u64(c, w, 1, "raw slot _approved[p0][B32] = 1");
        slot_map(key, B_TWIN, inner);
        ck(c, !raw_slot(c, v, key, w), "raw slot _approved[p0][B_twin32]: no net write");
    }
    buf_free(&hook);
}

/* ── MilestoneEscrow ───────────────────────────────────────────────────── */

static enc_t esc_args(const uint8_t *payer, const uint8_t *payee, const uint8_t *arb,
                      const uint8_t *const *amounts, size_t n, uint64_t deadline)
{
    enc_t e = E0();
    enc_word(&e, payer);
    enc_word(&e, payee);
    enc_word(&e, arb);
    enc_words(&e, amounts, n);
    enc_word(&e, U(deadline));
    return e;
}

static void esc_acct(ctx_t *c, const uint8_t esc[32], uint64_t un, uint64_t cr,
                     uint64_t wd, const char *what)
{
    uint8_t w[32];
    char m[160];
    view_at(c, esc, "accounting()", E0(), 0, w, what);
    snprintf(m, sizeof(m), "%s: unsettled", what);
    ck_u64(c, w, un, m);
    view_at(c, esc, "accounting()", E0(), 1, w, what);
    snprintf(m, sizeof(m), "%s: credited", what);
    ck_u64(c, w, cr, m);
    view_at(c, esc, "accounting()", E0(), 2, w, what);
    snprintf(m, sizeof(m), "%s: withdrawn", what);
    ck_u64(c, w, wd, m);
}

static void scen_escrow(ctx_t *c)
{
    static const char *UNAUTH = "EscrowUnauthorized(address)";
    static const char *SETTLED = "EscrowAlreadySettled(uint256,uint8)";
    static const char *NOTFUNDED = "EscrowNotFunded()";
    uint8_t e1[32], e2[32], e3[32], e4[32], self[32], x[32], fr[32], w[32], key[32];
    evm_tx_result_t r;
    uint64_t now = c->env.timestamp;
    uint64_t dl = now + 1000;

    /* constructor refusals */
    deploy_rev(c, S_A, K_ESCROW, esc_args(ZERO, B, C, ARGS(U(Q)), dl),
               "EscrowInvalidParty(address)", ARGS(ZERO), "zero payer refused");
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, A, C, ARGS(U(Q)), dl),
               "EscrowInvalidParty(address)", ARGS(A), "payee == payer refused");
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, B, ARGS(U(Q)), dl),
               "EscrowInvalidParty(address)", ARGS(B), "arbiter == payee refused");
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, ZERO, ARGS(U(Q)), dl),
               "EscrowInvalidParty(address)", ARGS(ZERO), "zero arbiter refused");
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, A, ARGS(U(Q)), dl),
               "EscrowInvalidParty(address)", ARGS(A), "arbiter == payer refused");
    /* the escrow's own (predicted CREATE) address as each party */
    create_addr(self, A, c->nonce[S_A]);
    deploy_rev(c, S_A, K_ESCROW, esc_args(self, B, C, ARGS(U(Q)), dl),
               "EscrowInvalidParty(address)", ARGS(self), "the escrow itself as payer refused");
    create_addr(self, A, c->nonce[S_A]);
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, self, C, ARGS(U(Q)), dl),
               "EscrowInvalidParty(address)", ARGS(self), "the escrow itself as payee refused");
    create_addr(self, A, c->nonce[S_A]);
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, self, ARGS(U(Q)), dl),
               "EscrowInvalidParty(address)", ARGS(self), "the escrow itself as arbiter refused");
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, C, NULL, 0, dl),
               "EscrowInvalidMilestones(uint256)", ARGS(U(0)), "0 milestones refused");
    {
        const uint8_t *m33[33];
        for (int i = 0; i < 33; i++) m33[i] = U(Q);
        deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, C, m33, 33, dl),
                   "EscrowInvalidMilestones(uint256)", ARGS(U(33)), "33 milestones refused");
    }
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, C, ARGS(U(Q), U(0)), dl),
               "EscrowInvalidAmount(uint256,uint256)", ARGS(U(1), U(0)), "zero amount refused");
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, C, ARGS(U(Q), U(Q + 1)), dl),
               "EscrowInvalidAmount(uint256,uint256)", ARGS(U(1), U(Q + 1)),
               "amount not a multiple of q refused");
    deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, C, ARGS(U(Q)), now),
               "EscrowInvalidDeadline(uint256)", ARGS(U(now)), "deadline == now refused");
    {
        /* big = floor((2^256 - 1) / q) * q: a q-multiple; two of them overflow */
        evm_u256 max, q, big;
        uint8_t mb[32], bigw[32], panic[32];
        memset(mb, 0xff, 32);
        evm_u256_from_be(&max, mb);
        evm_u256_from_u64(&q, Q);
        evm_u256_div(&big, &max, &q);
        evm_u256_mul(&big, &big, &q);
        evm_u256_to_be(bigw, &big);
        word_u64(panic, 0x11);
        deploy_rev(c, S_A, K_ESCROW, esc_args(A, B, C, ARGS(bigw, bigw), dl),
                   "Panic(uint256)", ARGS(panic), "an overflowing sum refused (Panic 0x11)");
    }

    /* E1: payer A, payee B, arbiter C, 4 milestones */
    const uint64_t AM[4] = { 3 * Q, 5 * Q, 7 * Q, 11 * Q };
    const uint64_t SUM = 26 * Q;
    if (deploy(c, S_A, K_ESCROW, esc_args(A, B, C, ARGS(U(AM[0]), U(AM[1]), U(AM[2]), U(AM[3])), dl),
               0, e1, NULL, "deploy escrow E1") != 0)
        return;
    view_at(c, e1, "parties()", E0(), 1, w, "parties().payee");
    ck_addr(c, w, B, "payee stored with its full 32 bytes");
    call_rev(c, S_A, e1, 0, "release(uint256)", E(U(0)), NOTFUNDED, NULL, 0,
             "release before funding refused");
    call_rev(c, S_C, e1, 0, "resolve(uint256,bool)", E(U(0), U(1)), NOTFUNDED, NULL, 0,
             "resolve before funding refused");
    call_rev(c, S_B, e1, SUM, "fund()", E0(), UNAUTH, ARGS(B), "fund by a non-payer refused");
    call_rev(c, S_A_TWIN, e1, SUM, "fund()", E0(), UNAUTH, ARGS(A_TWIN),
             "fund by the payer's twin refused");
    call_rev(c, S_A, e1, SUM - Q, "fund()", E0(), "EscrowWrongAmount(uint256,uint256)",
             ARGS(U(SUM - Q), U(SUM)), "fund with the wrong amount refused");
    if (call_ok(c, S_A, e1, SUM, "fund()", E0(), &r, "fund E1")) {
        ck_log(c, &r, e1, "Funded(address,uint256)", ARGS(A), "Funded");
        evm_tx_result_free(&r);
    }
    call_rev(c, S_A, e1, SUM, "fund()", E0(), "EscrowAlreadyFunded()", NULL, 0,
             "fund twice refused");
    ck_u64v(c, bal(c, e1), SUM, "escrow holds the sum");
    esc_acct(c, e1, SUM, 0, 0, "after funding");

    call_rev(c, S_B, e1, 0, "release(uint256)", E(U(0)), UNAUTH, ARGS(B), "release by the payee refused");
    call_rev(c, S_A, e1, 0, "resolve(uint256,bool)", E(U(0), U(1)), UNAUTH, ARGS(A),
             "resolve by the payer refused");
    call_rev(c, S_A, e1, 0, "release(uint256)", E(U(4)), "EscrowInvalidIndex(uint256)", ARGS(U(4)),
             "release of an invalid index refused");
    call_rev(c, S_C, e1, 0, "resolve(uint256,bool)", E(U(4), U(1)), "EscrowInvalidIndex(uint256)",
             ARGS(U(4)), "resolve of an invalid index refused");
    if (call_ok(c, S_A, e1, 0, "release(uint256)", E(U(0)), &r, "release(0)")) {
        ck_log(c, &r, e1, "Settled(uint256,uint8,address,uint256)", ARGS(U(0), B), "Settled(0)");
        evm_tx_result_free(&r);
    }
    call_ok(c, S_C, e1, 0, "resolve(uint256,bool)", E(U(1), U(1)), NULL, "resolve(1, payee)");
    call_ok(c, S_C, e1, 0, "resolve(uint256,bool)", E(U(2), U(0)), NULL, "resolve(2, payer)");
    at_time(c, dl - 1);
    call_rev(c, S_A, e1, 0, "refund(uint256)", E(U(3)), "EscrowBeforeDeadline(uint256)", ARGS(U(dl)),
             "refund at deadline - 1 refused");
    at_time(c, dl);
    call_ok(c, S_A, e1, 0, "refund(uint256)", E(U(3)), NULL, "refund(3) at the deadline");
    call_rev(c, S_A, e1, 0, "refund(uint256)", E(U(4)), "EscrowInvalidIndex(uint256)", ARGS(U(4)),
             "refund of an invalid index refused (at the deadline)");

    /* every pair of settlements on one milestone: the second reverts */
    {
        static const uint64_t st[4] = { 1, 1, 2, 2 };   /* Released, Released, Refunded, Refunded */
        for (uint64_t i = 0; i < 4; i++) {
            char m[120];
            snprintf(m, sizeof(m), "milestone %llu: second release refused", (unsigned long long)i);
            call_rev(c, S_A, e1, 0, "release(uint256)", E(U(i)), SETTLED, ARGS(U(i), U(st[i])), m);
            snprintf(m, sizeof(m), "milestone %llu: second resolve(payee) refused", (unsigned long long)i);
            call_rev(c, S_C, e1, 0, "resolve(uint256,bool)", E(U(i), U(1)), SETTLED, ARGS(U(i), U(st[i])), m);
            snprintf(m, sizeof(m), "milestone %llu: second resolve(payer) refused", (unsigned long long)i);
            call_rev(c, S_C, e1, 0, "resolve(uint256,bool)", E(U(i), U(0)), SETTLED, ARGS(U(i), U(st[i])), m);
            snprintf(m, sizeof(m), "milestone %llu: second refund refused", (unsigned long long)i);
            call_rev(c, S_A, e1, 0, "refund(uint256)", E(U(i)), SETTLED, ARGS(U(i), U(st[i])), m);
        }
    }
    view(c, e1, "creditOf(address)", E(B), w, "creditOf(B)");
    ck_u64(c, w, 8 * Q, "payee credit = 3 q + 5 q");
    view(c, e1, "creditOf(address)", E(A), w, "creditOf(A)");
    ck_u64(c, w, 18 * Q, "payer credit = 7 q + 11 q");
    view(c, e1, "creditOf(address)", E(B_TWIN), w, "creditOf(B_twin)");
    ck_u64(c, w, 0, "the payee's twin has no credit");
    esc_acct(c, e1, 0, SUM, 0, "after settling");

    /* raw slot (solc --storage-layout: slot 9 _credit) */
    slot_map(key, B, U(9));
    raw_slot(c, e1, key, w);
    ck_u64(c, w, 8 * Q, "raw slot _credit[B32] = 8 q");
    slot_map(key, B_TWIN, U(9));
    ck(c, !raw_slot(c, e1, key, w), "raw slot _credit[B_twin32]: no net write");

    /* withdraw */
    call_rev(c, S_C, e1, 0, "withdraw()", E0(), "EscrowNothingToWithdraw(address)", ARGS(C),
             "withdraw with zero credit refused");
    call_rev(c, S_B_TWIN, e1, 0, "withdraw()", E0(), "EscrowNothingToWithdraw(address)", ARGS(B_TWIN),
             "withdraw by the payee's twin refused");
    uint64_t b0 = bal(c, B);
    if (call_ok(c, S_B, e1, 0, "withdraw()", E0(), &r, "payee withdraws")) {
        ck_log(c, &r, e1, "Withdrawn(address,uint256)", ARGS(B), "Withdrawn");
        evm_tx_result_free(&r);
    }
    ck_u64v(c, bal(c, B) - b0, 8 * Q, "payee received exactly 8 q");
    call_rev(c, S_B, e1, 0, "withdraw()", E0(), "EscrowNothingToWithdraw(address)", ARGS(B),
             "withdraw twice refused");
    uint64_t a0 = bal(c, A);
    call_ok(c, S_A, e1, 0, "withdraw()", E0(), NULL, "payer withdraws");
    ck_u64v(c, bal(c, A) - a0, 18 * Q, "payer received exactly 18 q");
    esc_acct(c, e1, 0, 0, SUM, "after withdrawing");
    ck_u64v(c, bal(c, e1), 0, "escrow E1 empty");

    /* E2: a contract payee (reverting, then re-entering), forced value */
    if (deploy(c, S_A, K_ACTOR, E0(), 0, x, NULL, "deploy MockActor (payee)") != 0) return;
    if (deploy(c, S_A, K_FORCER, E0(), 0, fr, NULL, "deploy MockForcer") != 0) return;
    now = c->env.timestamp;
    if (deploy(c, S_A, K_ESCROW, esc_args(A, x, C, ARGS(U(2 * Q), U(4 * Q)), now + 1000),
               0, e2, NULL, "deploy escrow E2 (contract payee)") != 0)
        return;
    call_ok(c, S_A, e2, 6 * Q, "fund()", E0(), NULL, "fund E2");
    call_ok(c, S_A, e2, 0, "release(uint256)", E(U(0)), NULL, "release(0) to the contract payee");
    {
        buf_t wd;
        mk_call(&wd, "withdraw()", E0());
        actor_mode(c, x, MODE_REVERT, NULL, NULL);
        actor_act(c, x, e2, &wd, NULL, "payee (reverting) calls withdraw");
        view(c, x, "lastOk()", E0(), w, "lastOk()");
        ck_u64(c, w, 0, "withdraw to a reverting payee failed");
        view(c, x, "lastErr()", E0(), w, "lastErr()");
        ck_sel(c, w, "EscrowPaymentFailed(address,uint256)", "error = EscrowPaymentFailed");
        view(c, e2, "creditOf(address)", E(x), w, "creditOf(payee)");
        ck_u64(c, w, 2 * Q, "the failed withdraw kept the credit");
        ck_u64v(c, bal(c, e2), 6 * Q, "no value left on the failed withdraw");

        actor_mode(c, x, MODE_REENTER, e2, &wd);
        actor_act(c, x, e2, &wd, NULL, "payee (re-entering) calls withdraw");
        view(c, x, "lastOk()", E0(), w, "lastOk()");
        ck_u64(c, w, 1, "the outer withdraw succeeded");
        view(c, x, "reErr()", E0(), w, "reErr()");
        ck_sel(c, w, "ReentrantCall()", "the re-entering withdraw was refused");
        view(c, x, "received()", E0(), w, "received()");
        ck_u64(c, w, 2 * Q, "the payee was paid exactly once (2 q)");
        view(c, e2, "creditOf(address)", E(x), w, "creditOf(payee)");
        ck_u64(c, w, 0, "credit cleared");
        buf_free(&wd);
    }
    call_ok(c, S_C, e2, 0, "resolve(uint256,bool)", E(U(1), U(0)), NULL, "resolve(1, payer)");
    esc_acct(c, e2, 0, 4 * Q, 2 * Q, "E2 before forcing");
    rev_tx(c, S_D, e2, Q, NULL, NULL, NULL, 0, "a plain value send to the escrow is refused");
    call_ok(c, S_D, fr, 3 * Q, "force(address)", E(e2), NULL, "SELFDESTRUCT forces 3 q into E2");
    ck_u64v(c, bal(c, e2), 7 * Q, "E2 balance = 4 q + 3 q forced");
    esc_acct(c, e2, 0, 4 * Q, 2 * Q, "forced value is never credited");
    view(c, e2, "creditOf(address)", E(A), w, "creditOf(A)");
    ck_u64(c, w, 4 * Q, "payer credit unchanged by the forced value");
    call_ok(c, S_A, e2, 0, "withdraw()", E0(), NULL, "payer withdraws 4 q");
    ck_u64v(c, bal(c, e2), 3 * Q, "the forced 3 q stay locked");
    call_rev(c, S_A, e2, 0, "withdraw()", E0(), "EscrowNothingToWithdraw(address)", ARGS(A),
             "nothing more to withdraw");

    /* E3: fund at the deadline refused; refund before funding refused */
    now = c->env.timestamp;
    if (deploy(c, S_A, K_ESCROW, esc_args(A, B, C, ARGS(U(Q)), now + 10), 0, e3, NULL,
               "deploy escrow E3") != 0)
        return;
    at_time(c, now + 10);
    call_rev(c, S_A, e3, Q, "fund()", E0(), "EscrowDeadlinePassed(uint256)", ARGS(U(now + 10)),
             "fund at the deadline refused");
    call_rev(c, S_A, e3, 0, "refund(uint256)", E(U(0)), NOTFUNDED, NULL, 0,
             "refund before funding refused");
    call_rev(c, S_A, e3, 0, "release(uint256)", E(U(0)), NOTFUNDED, NULL, 0,
             "release before funding refused (after the deadline)");

    /* E4: the deadline gives eligibility, not priority */
    create_addr(self, A, c->nonce[S_A]);
    now = c->env.timestamp;
    if (deploy(c, S_A, K_ESCROW, esc_args(A, B, C, ARGS(U(Q), U(Q)), now + 10), 0, e4, NULL,
               "deploy escrow E4") != 0)
        return;
    ck_word(c, e4, self, "E4 at the predicted address");
    call_ok(c, S_A, e4, 2 * Q, "fund()", E0(), NULL, "fund E4");
    at_time(c, now + 20);
    call_ok(c, S_C, e4, 0, "resolve(uint256,bool)", E(U(0), U(1)), NULL,
            "resolve(0, payee) after the deadline still settles");
    call_ok(c, S_A, e4, 0, "release(uint256)", E(U(1)), NULL,
            "release(1) after the deadline still settles");
    call_rev(c, S_A, e4, 0, "refund(uint256)", E(U(1)), SETTLED, ARGS(U(1), U(1)),
             "refund after a release on the same milestone refused");
    esc_acct(c, e4, 0, 2 * Q, 0, "E4");
}

/* ── ticket mock: transfer / stipend vs full gas ───────────────────────── */

static void scen_ticket_mock(ctx_t *c)
{
    uint8_t ts[32];
    evm_tx_result_t r;
    if (deploy(c, S_A, K_TICKETSENDER, E0(), 0, ts, NULL, "deploy MockTicketSender") != 0) return;
    ok_tx(c, S_D, ts, 5 * Q, NULL, NULL, "send 5 q to the ticket sender");
    call_rev(c, S_A, ts, 0, "pushTransfer(address,uint256)", E(TICKET, U(Q)), NULL, NULL, 0,
             "transfer() to the ticket address reverts");
    {
        enc_t e = E0();
        enc_word(&e, TICKET);
        enc_word(&e, U(Q));
        enc_bytes(&e, FP, 64);
        call_rev(c, S_A, ts, 0, "pushStipend(address,uint256,bytes)", e, "TicketCallFailed()",
                 NULL, 0, "a 64-byte ticket call with only the 2 300 stipend fails");
    }
    ck_u64v(c, bal(c, ts), 5 * Q, "no balance moved by the refused ticket calls");
    {
        enc_t e = E0();
        enc_word(&e, TICKET);
        enc_word(&e, U(Q));
        enc_bytes(&e, FP, 64);
        if (call_ok(c, S_A, ts, 0, "pushFull(address,uint256,bytes)", e, &r,
                    "the same call forwarding all gas creates the ticket")) {
            ck_ticket(c, &r, Q, FP, "full-gas ticket");
            evm_tx_result_free(&r);
        }
    }
    ck_u64v(c, bal(c, ts), 4 * Q, "the ticket sender's balance dropped by 1 q");
}

/* ── ML-DSA-87 companion library (MLDSA87, MLDSA87Attested) ────────────── */

#define PK_LEN      QGP_DSA87_PUBLICKEYBYTES
#define SIG_LEN     QGP_DSA87_SIGNATURE_BYTES
#define ATT_CTX     "nodus.evm.attest.v1"            /* the FIPS 204 context */
#define ATT_CTX_LEN 19u
#define MSG_MAX     65536u
/* A far expiry: block time stays below it until the very last case. */
#define EXPIRY      (T0 + 100000ull)

/* action argument lists (the three Approve-shaped actions share them) */
#define AP_ARGS     "(uint256,uint64,address,uint256,address,bytes,bytes)"
#define SUBMIT_FN   "submit(uint256,uint64,address,address,uint256,bytes,bytes,bytes)"
#define INVALID_SIG "MLDSA87InvalidSignature(address)"
#define NONCE_USED  "AttestationNonceUsed(address,uint256)"
#define HDR_MISMATCH "AttestationHeaderMismatch()"
#define B_APPROVE_MSG "approveMessage(uint256,address,uint256,uint64,address,uint256,address)"
#define B_MISORD_MSG  "misorderedMessage(uint256,address,uint256,uint64,address,uint256,address)"

typedef struct {
    uint8_t pk[PK_LEN];
    uint8_t sk[QGP_DSA87_SECRETKEYBYTES];
    uint8_t addr[32];                    /* SHA3-512(pk)[0..32] */
} sigkey_t;

static sigkey_t KEYS[4];                 /* 0,1,2 = the 2-of-3 signers; 3 = an outsider */
static uint8_t  CHAIN32[32];             /* the engine's chain id (chain_id_word) */

/* The four signing keys, from fixed seeds (qgp_dsa87_keypair_derand: no
 * randomness); each signer's account is its address. Called once, after
 * init_inputs and before any ctx_open. */
static void init_keys(void)
{
    for (int i = 0; i < 4; i++) {
        uint8_t seed[32], h[QGP_SHA3_512_DIGEST_LENGTH];
        for (int k = 0; k < 32; k++) seed[k] = (uint8_t)(0x40 * (i + 1) + k);
        if (qgp_dsa87_keypair_derand(KEYS[i].pk, KEYS[i].sk, seed) != 0)
            fatal("qgp_dsa87_keypair_derand");
        if (qgp_sha3_512(KEYS[i].pk, PK_LEN, h) != 0) fatal("qgp_sha3_512");
        memcpy(KEYS[i].addr, h, 32);
        if (!high_nonzero(KEYS[i].addr)) fatal("a signer address with zero high bytes");
        memcpy(ACC[S_SIG0 + i], KEYS[i].addr, 32);
    }
    for (int i = 0; i < 32; i++) CHAIN32[i] = (uint8_t)(0xc0 + i);
}

/* hex text -> bytes. @return 0, -1 odd length / non-hex / over cap */
static int hex_bytes(const char *s, uint8_t *out, size_t cap, size_t *n)
{
    size_t len = strlen(s);
    if (len % 2 != 0 || len / 2 > cap) return -1;
    for (size_t i = 0; i < len / 2; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi * 16 + lo);
    }
    *n = len / 2;
    return 0;
}

/* decimal text -> a 256-bit big-endian word. @return 0, -1 not a number /
 * above 2^256-1 */
static int dec_word(const char *s, uint8_t out[32])
{
    memset(out, 0, 32);
    if (!*s) return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        unsigned carry = (unsigned)(*s - '0');
        for (int i = 31; i >= 0; i--) {
            unsigned v = (unsigned)out[i] * 10u + carry;
            out[i] = (uint8_t)v;
            carry = v >> 8;
        }
        if (carry) return -1;
    }
    return 0;
}

/* The `bytes` a view returns, unwrapped from its ABI encoding. */
static int view_bytes(ctx_t *c, const uint8_t *to, const char *sig, enc_t e,
                      buf_t *out, const char *what)
{
    evm_tx_result_t r;
    int ok = 0;
    memset(out, 0, sizeof(*out));
    if (!call_ok(c, S_VIEW, to, 0, sig, e, &r, what)) return -1;
    if (r.output_len >= 64) {
        uint64_t off = 0, len = 0;
        int clean = 1;
        for (int i = 0; i < 24; i++)
            if (r.output[i] || r.output[32 + i]) clean = 0;
        for (int i = 24; i < 32; i++) {
            off = (off << 8) | r.output[i];
            len = (len << 8) | r.output[32 + i];
        }
        if (clean && off == 32 && len <= r.output_len - 64) {
            buf_put(out, r.output + 64, (size_t)len);
            ok = 1;
        }
    }
    evm_tx_result_free(&r);
    ck(c, ok, what);
    return ok ? 0 : -1;
}

/* sig over msg under the FIPS 204 context (ctx, ctxlen); ctx NULL = empty */
static void att_sign(const sigkey_t *k, const buf_t *msg, const uint8_t *ctx,
                     size_t ctxlen, uint8_t sig[SIG_LEN])
{
    static const uint8_t one = 0;
    size_t sl = 0;
    if (qgp_dsa87_sign_ctx(sig, &sl, msg->n ? msg->b : &one, msg->n, ctx, ctxlen,
                           k->sk) != 0 || sl != SIG_LEN)
        fatal("ML-DSA-87 signing");
}

static void att_sign_ok(const sigkey_t *k, const buf_t *msg, uint8_t sig[SIG_LEN])
{
    att_sign(k, msg, (const uint8_t *)ATT_CTX, ATT_CTX_LEN, sig);
}

/* The Approve-shaped message through a mock's pure builder `bsig`
 * (approveMessage / misorderedMessage), for explicit chain id and contract. */
static void bld_approve(ctx_t *c, const char *bsig, const uint8_t *mock,
                        const uint8_t chain[32], const uint8_t *verifying,
                        uint64_t nonce, uint64_t expiry, const uint8_t signer[32],
                        uint64_t amount, const uint8_t to[32], buf_t *out)
{
    enc_t e = E0();
    enc_word(&e, chain);
    enc_word(&e, verifying);
    enc_word(&e, U(nonce));
    enc_word(&e, U(expiry));
    enc_word(&e, signer);
    enc_word(&e, U(amount));
    enc_word(&e, to);
    view_bytes(c, mock, bsig, e, out, bsig);
}

static void bld_submit(ctx_t *c, const uint8_t *mock, uint64_t nonce, uint64_t expiry,
                       const uint8_t signer[32], const uint8_t target[32],
                       uint64_t value, const uint8_t *data, size_t dn, buf_t *out)
{
    enc_t e = E0();
    enc_word(&e, CHAIN32);
    enc_word(&e, mock);
    enc_word(&e, U(nonce));
    enc_word(&e, U(expiry));
    enc_word(&e, signer);
    enc_word(&e, target);
    enc_word(&e, U(value));
    enc_bytes(&e, data, dn);
    view_bytes(c, mock,
               "submitMessage(uint256,address,uint256,uint64,address,address,uint256,bytes)",
               e, out, "submitMessage");
}

/* calldata of fn(nonce, expiry, signer, amount, to, pk, sig) */
static void data_ap(buf_t *d, const char *fn, uint64_t nonce, uint64_t expiry,
                    const uint8_t signer[32], uint64_t amount, const uint8_t to[32],
                    const uint8_t *pk, size_t pkn, const uint8_t *sg, size_t sgn)
{
    enc_t e = E0();
    enc_word(&e, U(nonce));
    enc_word(&e, U(expiry));
    enc_word(&e, signer);
    enc_word(&e, U(amount));
    enc_word(&e, to);
    enc_bytes(&e, pk, pkn);
    enc_bytes(&e, sg, sgn);
    mk_call(d, fn, e);
}

static void data_submit(buf_t *d, uint64_t nonce, uint64_t expiry,
                        const uint8_t signer[32], const uint8_t target[32],
                        uint64_t value, const uint8_t *data, size_t dn,
                        const sigkey_t *k, const uint8_t *sg)
{
    enc_t e = E0();
    enc_word(&e, U(nonce));
    enc_word(&e, U(expiry));
    enc_word(&e, signer);
    enc_word(&e, target);
    enc_word(&e, U(value));
    enc_bytes(&e, data, dn);
    enc_bytes(&e, k->pk, PK_LEN);
    enc_bytes(&e, sg, SIG_LEN);
    mk_call(d, SUBMIT_FN, e);
}

/* Approve attestation for (mock, chain) signed by `k` for the claimed `signer`. */
static void ap_sign(ctx_t *c, const uint8_t *mock, const uint8_t chain[32],
                    uint64_t nonce, uint64_t expiry, const sigkey_t *k,
                    const uint8_t signer[32], uint64_t amount, const uint8_t to[32],
                    uint8_t sg[SIG_LEN])
{
    buf_t msg;
    bld_approve(c, B_APPROVE_MSG, mock, chain, mock, nonce, expiry, signer, amount,
                to, &msg);
    att_sign_ok(k, &msg, sg);
    buf_free(&msg);
}

/* send d from S_OUT to `to`, expecting revert MLDSA87InvalidSignature(signer); frees d */
static void rev_inv(ctx_t *c, const uint8_t *to, buf_t *d, const uint8_t signer[32],
                    const char *what)
{
    rev_tx(c, S_OUT, to, 0, d, INVALID_SIG, ARGS(signer), what);
    buf_free(d);
}

/* send d from S_OUT, expecting revert `esig(signer, U(nonce))`; frees d */
static void rev_used(ctx_t *c, const uint8_t *to, buf_t *d, const uint8_t signer[32],
                     uint64_t nonce, const char *what)
{
    rev_tx(c, S_OUT, to, 0, d, NONCE_USED, ARGS(signer, U(nonce)), what);
    buf_free(d);
}

static void ck_bool(ctx_t *c, const uint8_t *to, const char *sig, enc_t e,
                    uint64_t want, const char *what)
{
    uint8_t w[32];
    view(c, to, sig, e, w, what);
    ck_u64(c, w, want, what);
}

/* ── the message fixture test/fixtures/attest_v1.txt ───────────────────── */

typedef struct {
    char     name[16];
    char     action[96];
    uint8_t  atype[32], chain[32], contract[32], signer[32], nonce[32], expiry[32];
    char     args[1024];
    uint8_t *msg;
    size_t   msglen;
    unsigned have;                       /* a bit per field; all 9 are required */
} fxcase_t;

#define FX_MAX   4

static const char *g_dir;                /* the out/ directory (argv[1] / default) */

static int fx_load(const char *dir, fxcase_t *cs, size_t *ncs)
{
    char path[1100];
    int pn = snprintf(path, sizeof(path), "%s/../test/fixtures/attest_v1.txt", dir);
    if (pn < 0 || (size_t)pn >= sizeof(path)) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "  [FAIL] fixture: missing %s\n", path);
        return -1;
    }
    size_t cap = 8192, n = 0;
    char *txt = malloc(cap);
    if (!txt) fatal("oom");
    int ch;
    while ((ch = fgetc(f)) != EOF) {
        if (n + 2 >= cap) {
            cap *= 2;
            char *x = realloc(txt, cap);
            if (!x) fatal("oom");
            txt = x;
        }
        txt[n++] = (char)ch;
    }
    txt[n] = 0;
    fclose(f);
    memset(cs, 0, FX_MAX * sizeof(*cs));
    *ncs = 0;
    int bad = 0;
    char *end = txt + n;
    for (char *line = txt, *next; line < end; line = next) {
        char *nl = memchr(line, '\n', (size_t)(end - line));
        if (nl) {
            *nl = 0;
            next = nl + 1;
        } else {
            next = end;
        }
        if (line[0] == '#' || line[0] == 0) continue;
        char *val = strchr(line, ' ');
        if (!val) { bad = 1; continue; }
        *val++ = 0;
        if (strcmp(line, "case") == 0) {
            if (*ncs == FX_MAX) { bad = 1; break; }
            snprintf(cs[*ncs].name, sizeof(cs[*ncs].name), "%s", val);
            (*ncs)++;
            continue;
        }
        if (*ncs == 0) { bad = 1; continue; }
        fxcase_t *k = &cs[*ncs - 1];
        size_t got = 0;
        int rc = 0;
        if (strcmp(line, "action") == 0) {
            snprintf(k->action, sizeof(k->action), "%s", val); k->have |= 1u;
        } else if (strcmp(line, "actiontype") == 0) {
            rc = hex_bytes(val, k->atype, 32, &got); if (got != 32) rc = -1; k->have |= 2u;
        } else if (strcmp(line, "chain") == 0) {
            rc = hex_bytes(val, k->chain, 32, &got); if (got != 32) rc = -1; k->have |= 4u;
        } else if (strcmp(line, "contract") == 0) {
            rc = hex_bytes(val, k->contract, 32, &got); if (got != 32) rc = -1; k->have |= 8u;
        } else if (strcmp(line, "signer") == 0) {
            rc = hex_bytes(val, k->signer, 32, &got); if (got != 32) rc = -1; k->have |= 16u;
        } else if (strcmp(line, "nonce") == 0) {
            rc = dec_word(val, k->nonce); k->have |= 32u;
        } else if (strcmp(line, "expiry") == 0) {
            rc = dec_word(val, k->expiry); k->have |= 64u;
        } else if (strcmp(line, "args") == 0) {
            snprintf(k->args, sizeof(k->args), "%s", val); k->have |= 128u;
        } else if (strcmp(line, "message") == 0) {
            k->msg = malloc(strlen(val) / 2 + 1);
            if (!k->msg) fatal("oom");
            rc = hex_bytes(val, k->msg, strlen(val) / 2 + 1, &k->msglen); k->have |= 256u;
        } else {
            rc = -1;
        }
        if (rc != 0) bad = 1;
    }
    free(txt);
    for (size_t i = 0; i < *ncs; i++)
        if ((cs[i].have & 0x1ffu) != 0x1ffu) bad = 1;
    return bad ? -1 : 0;
}

/* split `args` at spaces into at most `max` tokens (in place) */
static size_t fx_tokens(char *args, char **tok, size_t max)
{
    size_t n = 0;
    for (char *p = args; *p && n < max;) {
        while (*p == ' ') *p++ = 0;
        if (!*p) break;
        tok[n++] = p;
        while (*p && *p != ' ') p++;
    }
    return n;
}

/* The mock's pure builders reproduce the fixture's message bytes for every
 * case, and the mock's two actionType constants (the compiler's compile-time
 * keccak256 of the action text) equal the fixture's actiontype words (the
 * tree's keccak256.c) — the compiler-vs-tree hash check. */
static void scen_fixture(ctx_t *c, const uint8_t *mock)
{
    fxcase_t cs[FX_MAX];
    size_t ncs = 0;
    int have_static = 0, have_dynamic = 0;
    uint8_t w[32];

    if (fx_load(g_dir, cs, &ncs) != 0) {
        ck(c, 0, "fixture attest_v1.txt loaded and well-formed");
        for (size_t i = 0; i < ncs; i++) free(cs[i].msg);
        return;
    }
    ck(c, ncs == 2, "fixture has exactly the two cases");
    for (size_t i = 0; i < ncs; i++) {
        fxcase_t *k = &cs[i];
        char *tok[4] = { NULL, NULL, NULL, NULL };
        size_t nt = fx_tokens(k->args, tok, 4);
        buf_t got;
        memset(&got, 0, sizeof(got));
        if (strcmp(k->name, "static") == 0) {
            uint8_t amount[32] = { 0 }, to[32] = { 0 };
            size_t tn = 0;
            have_static = 1;
            ck(c, nt == 2 && dec_word(tok[0], amount) == 0 &&
                  hex_bytes(tok[1], to, 32, &tn) == 0 && tn == 32,
               "fixture static: args are (uint256, address)");
            view(c, mock, "APPROVE()", E0(), w, "APPROVE()");
            ck_word(c, w, k->atype,
                    "Approve(uint256,address): compiler keccak256 = the fixture's tree keccak256");
            enc_t e = E0();
            enc_word(&e, k->chain);
            enc_word(&e, k->contract);
            enc_word(&e, k->nonce);
            enc_word(&e, k->expiry);
            enc_word(&e, k->signer);
            enc_word(&e, amount);
            enc_word(&e, to);
            view_bytes(c, mock, B_APPROVE_MSG, e, &got, "fixture static: approveMessage");
        } else if (strcmp(k->name, "dynamic") == 0) {
            uint8_t target[32] = { 0 }, value[32] = { 0 }, data[64] = { 0 };
            size_t tn = 0, dn = 0;
            have_dynamic = 1;
            ck(c, nt == 3 && hex_bytes(tok[0], target, 32, &tn) == 0 && tn == 32 &&
                  dec_word(tok[1], value) == 0 &&
                  hex_bytes(tok[2], data, sizeof(data), &dn) == 0,
               "fixture dynamic: args are (address, uint256, bytes)");
            view(c, mock, "SUBMIT()", E0(), w, "SUBMIT()");
            ck_word(c, w, k->atype,
                    "Submit(address,uint256,bytes): compiler keccak256 = the fixture's tree keccak256");
            enc_t e = E0();
            enc_word(&e, k->chain);
            enc_word(&e, k->contract);
            enc_word(&e, k->nonce);
            enc_word(&e, k->expiry);
            enc_word(&e, k->signer);
            enc_word(&e, target);
            enc_word(&e, value);
            enc_bytes(&e, data, dn);
            view_bytes(c, mock,
                       "submitMessage(uint256,address,uint256,uint64,address,address,uint256,bytes)",
                       e, &got, "fixture dynamic: submitMessage");
        } else {
            ck(c, 0, "fixture case has a known name");
        }
        ck(c, got.n == k->msglen && got.n > 0 && memcmp(got.b, k->msg, got.n) == 0,
           "the mock's builder reproduces the fixture message byte for byte");
        buf_free(&got);
    }
    ck(c, have_static && have_dynamic, "fixture has the static and the dynamic case");
    for (size_t i = 0; i < ncs; i++) free(cs[i].msg);
}

/* ── the scenarios ─────────────────────────────────────────────────────── */

/* the decision's TAG_ATTEST_V1 = keccak256("nodus.evm.attest.message.v1")
 * (decisions/2026-10-21-mldsa87-evm-precompile.md, "TAG_ATTEST_V1") */
static const uint8_t TAG_DECISION[32] = {
    0x99, 0xe8, 0x05, 0xe3, 0x50, 0x26, 0xbc, 0xe8, 0x60, 0xf6, 0xbb, 0xcd,
    0xa7, 0x46, 0x6a, 0x18, 0xfd, 0x6a, 0x7b, 0xfe, 0x81, 0xd1, 0x52, 0x44,
    0x94, 0xfe, 0x54, 0x1c, 0x94, 0x88, 0xa4, 0x3d };

/* The mldsa_precompile = 0 state: the precompile address is an ordinary
 * account, so a VALID signature is not verified: verify reports ok == false
 * and everything built on it reverts. */
static void scen_mldsa_off(ctx_t *c)
{
    uint8_t m[32], w[32], sg[SIG_LEN];
    buf_t msg, d;

    if (deploy(c, S_A, K_ATTESTED, E(KEYS[0].addr, KEYS[1].addr, KEYS[2].addr), 0, m,
               NULL, "deploy MockAttested (switch off)") != 0)
        return;
    bld_approve(c, B_APPROVE_MSG, m, CHAIN32, m, 1, EXPIRY, KEYS[0].addr, 1000, B, &msg);
    att_sign_ok(&KEYS[0], &msg, sg);

    data_ap(&d, "approve" AP_ARGS, 1, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "switch off: a valid attestation is refused");
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(1)), 0,
            "switch off: the nonce was not consumed");

    {
        enc_t e = E0();
        enc_bytes(&e, KEYS[0].pk, PK_LEN);
        enc_bytes(&e, sg, SIG_LEN);
        enc_bytes(&e, msg.b, msg.n);
        view_at(c, m, "verifyRaw(bytes,bytes,bytes)", e, 0, w, "verifyRaw.ok");
        ck_u64(c, w, 0, "switch off: verify reports ok == false for a valid signature");
    }
    {
        enc_t e = E0();
        enc_bytes(&e, KEYS[0].pk, PK_LEN);
        enc_bytes(&e, sg, SIG_LEN);
        enc_bytes(&e, msg.b, msg.n);
        view_at(c, m, "verifyRaw(bytes,bytes,bytes)", e, 1, w, "verifyRaw.signer");
        ck_word(c, w, ZERO, "switch off: verify returns signer 0");
    }
    {
        enc_t e = E0();
        enc_word(&e, KEYS[0].addr);
        enc_bytes(&e, KEYS[0].pk, PK_LEN);
        enc_bytes(&e, sg, SIG_LEN);
        enc_bytes(&e, msg.b, msg.n);
        buf_t rd;
        mk_call(&rd, "requireSignerRaw(address,bytes,bytes,bytes)", e);
        rev_tx(c, S_OUT, m, 0, &rd, INVALID_SIG, ARGS(KEYS[0].addr),
               "switch off: requireSigner reverts");
        buf_free(&rd);
    }
    buf_free(&msg);
}

/* the starved-precompile scan: requireSigner in a frame capped at gasCap */
static void scen_starved(ctx_t *c, const uint8_t *m)
{
    uint8_t sg[SIG_LEN], want[36], sel[4];
    buf_t msg;
    uint64_t first_hit = 0, first_ok = 0;
    int unexpected = 0;

    /* A MAXIMUM-size message (65 536 bytes), not an Approve-sized one. The
     * window this scan looks for exists only when the caller keeps enough
     * gas after the starved STATICCALL to revert WITH data: the caller
     * keeps 1/64 of what it had (EIP-150), i.e. about precompile cost / 63.
     * Measured 2026-10-22 (ORCH): with a 288-byte message (cost 25 108,
     * ~398 gas kept) the `default` (unoptimized) build never reverts with
     * MLDSA87InvalidSignature — every starved call runs out of gas in the
     * caller and reverts EMPTY, so the scan jumped from empty failures
     * straight to success at cap 34 944 (the `optimize` build had the window
     * 23 808 .. 33 024). With 65 536 bytes (cost 49 576, ~787 kept) both
     * builds show it (default 162 304 .. 186 432, optimize 150 656 ..
     * 184 704). Both outcomes are refusals; only the proof that the call
     * was reached needs the larger message. */
    {
        static uint8_t big[65536];
        for (size_t i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i * 7 + 1);
        memset(&msg, 0, sizeof(msg));
        buf_put(&msg, big, sizeof(big));
    }
    att_sign_ok(&KEYS[0], &msg, sg);
    sel_of(INVALID_SIG, sel);
    memcpy(want, sel, 4);
    memcpy(want + 4, KEYS[0].addr, 32);

    /* step 64: the windows measured above are thousands of gas wide */
    for (uint64_t cap = 8000; cap <= 400000 && !first_ok; cap += 64) {
        evm_tx_result_t r;
        buf_t d;
        enc_t e = E0();
        enc_word(&e, U(cap));
        enc_word(&e, KEYS[0].addr);
        enc_bytes(&e, KEYS[0].pk, PK_LEN);
        enc_bytes(&e, sg, SIG_LEN);
        enc_bytes(&e, msg.b, msg.n);
        mk_call(&d, "requireSignerWithGas(uint256,address,bytes,bytes,bytes)", e);
        int rc = send_tx(c, S_OUT, m, 0, &d, &r);
        buf_free(&d);
        if (rc != 0 || r.status != EVM_EXEC_SUCCESS || r.output_len < 96) {
            unexpected = 1;
        } else {
            /* (bool ok, bytes ret): word 0 = ok, word 1 = offset, then len + data */
            int ok = r.output[31] == 1;
            uint64_t len = 0;
            for (int i = 24; i < 32; i++) len = (len << 8) | r.output[64 + i];
            if (ok && len == 0) {
                first_ok = cap;
            } else if (!ok && len == 36 && r.output_len >= 96 + 36 &&
                       memcmp(r.output + 96, want, 36) == 0) {
                if (!first_hit) first_hit = cap;
            } else if (!ok && len == 0) {
                /* the frame ran out of gas before the precompile call */
            } else {
                unexpected = 1;
            }
        }
        evm_tx_result_free(&r);
    }
    buf_free(&msg);
    ck(c, !unexpected, "starved scan: every outcome is OOG-before-call, "
                       "InvalidSignature(signer), or success");
    ck(c, first_hit != 0, "starved scan: some cap reaches the precompile call and it "
                          "fails for lack of gas -> MLDSA87InvalidSignature(signer)");
    ck(c, first_ok != 0 && first_hit < first_ok,
       "starved scan: a larger cap succeeds (the signature was valid all along)");
}

/* the mldsa_precompile = 1 state */
static void scen_mldsa(ctx_t *c)
{
    static const uint8_t DATA5[5] = { 0xde, 0xad, 0xbe, 0xef, 0x01 };
    uint8_t m[32], m2[32], x[32], w[32], pid[32], atype[32], gtype[32];
    uint8_t sg[SIG_LEN], sg2[SIG_LEN];
    uint8_t chain2[32];
    evm_tx_result_t r;
    buf_t msg, d;

    /* ── pins ── */
    ck(c, memcmp(TICKET, evm_mldsa87_addr.b, 32) != 0,
       "the test ticket address differs from the ML-DSA tag address");
    ck(c, c->ec.mldsa_precompile == 1, "this state has the precompile switch on");
    if (deploy(c, S_A, K_ATTESTED, E(KEYS[0].addr, KEYS[1].addr, KEYS[2].addr), 0, m,
               NULL, "deploy MockAttested") != 0)
        return;
    if (deploy(c, S_A, K_ATTESTED, E(KEYS[0].addr, KEYS[1].addr, KEYS[2].addr), 0, m2,
               NULL, "deploy MockAttested #2") != 0)
        return;
    view(c, m, "tagAttestV1()", E0(), w, "tagAttestV1()");
    ck_word(c, w, TAG_DECISION, "TAG_ATTEST_V1 = the decision's 99e805e3...a43d");
    view(c, m, "precompileAddress()", E0(), w, "precompileAddress()");
    ck_word(c, w, evm_mldsa87_addr.b, "MLDSA87.PRECOMPILE = evm_mldsa87_addr (all 32 bytes)");
    view(c, m, "APPROVE()", E0(), atype, "APPROVE()");
    view(c, m, "GUARDED()", E0(), gtype, "GUARDED()");
    scen_fixture(c, m);

    /* ── a valid attestation applies its action once ── */
    ap_sign(c, m, CHAIN32, 1, EXPIRY, &KEYS[0], KEYS[0].addr, 1000, B, sg);
    data_ap(&d, "approve" AP_ARGS, 1, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg, SIG_LEN);
    if (ok_tx(c, S_OUT, m, 0, &d, &r, "valid attestation")) {
        ck_log(c, &r, m, "AttestationConsumed(address,uint256,bytes32)",
               ARGS(KEYS[0].addr, U(1), atype), "AttestationConsumed");
        ck_log(c, &r, m, "Approved(address,address,uint256)", ARGS(KEYS[0].addr, B),
               "Approved");
        evm_tx_result_free(&r);
    }
    ck_bool(c, m, "allowance(address)", E(B), 1000, "the action ran once: allowance[B]");
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(1)), 1,
            "nonce 1 of signer 0 is used");

    /* ── replay: the same call, and a second valid signature over the same nonce ── */
    rev_used(c, m, &d, KEYS[0].addr, 1, "replay of the same call refused");
    ap_sign(c, m, CHAIN32, 1, EXPIRY, &KEYS[0], KEYS[0].addr, 1000, B, sg2);
    data_ap(&d, "approve" AP_ARGS, 1, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg2, SIG_LEN);
    rev_used(c, m, &d, KEYS[0].addr, 1,
             "a second valid signature over the same nonce is refused");
    ck_bool(c, m, "allowance(address)", E(B), 1000, "allowance[B] unchanged by the replays");

    /* ── a changed parameter / nonce, another contract / chain / action ── */
    ap_sign(c, m, CHAIN32, 2, EXPIRY, &KEYS[0], KEYS[0].addr, 1000, B, sg);
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1001, B, KEYS[0].pk, PK_LEN,
            sg, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "changed amount, correct header: refused");
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, C, KEYS[0].pk, PK_LEN,
            sg, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "changed recipient, correct header: refused");
    data_ap(&d, "approve" AP_ARGS, 3, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "changed nonce, correct header: refused");
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY + 1, KEYS[0].addr, 1000, B, KEYS[0].pk,
            PK_LEN, sg, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "changed expiry, correct header: refused");
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[1].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg, SIG_LEN);
    rev_inv(c, m, &d, KEYS[1].addr, "claimed signer changed, correct header: refused");
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(2)), 0,
            "the refusals left nonce 2 unused");

    /* signed for contract m, presented to m2 */
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg, SIG_LEN);
    rev_inv(c, m2, &d, KEYS[0].addr, "an attestation for one contract is refused by another");
    /* signed for another chain id */
    memcpy(chain2, CHAIN32, 32);
    chain2[31] ^= 1;
    ap_sign(c, m, chain2, 2, EXPIRY, &KEYS[0], KEYS[0].addr, 1000, B, sg2);
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg2, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "an attestation for another chain id is refused");
    /* another actionType, same parameter layout (word 3 of the header) */
    bld_approve(c, B_APPROVE_MSG, m, CHAIN32, m, 2, EXPIRY, KEYS[0].addr, 1000, B, &msg);
    memcpy(msg.b + 96, gtype, 32);
    att_sign_ok(&KEYS[0], &msg, sg2);
    buf_free(&msg);
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg2, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "an attestation for another action is refused");

    /* ── signature faults ── */
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[3].pk, PK_LEN,
            sg, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "a wrong key's pk presented for the signer: refused");
    ap_sign(c, m, CHAIN32, 2, EXPIRY, &KEYS[3], KEYS[0].addr, 1000, B, sg2);
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[3].pk, PK_LEN,
            sg2, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "a valid signature by another key for this signer: refused");
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg2, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "another key's signature under the signer's pk: refused");
    memcpy(sg2, sg, SIG_LEN);
    sg2[100] ^= 1;
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg2, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "a correctly sized signature with one byte flipped: refused");
    memset(sg2, 0, SIG_LEN);
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg2, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "an all-zero signature of the right size: refused");
    bld_approve(c, B_APPROVE_MSG, m, CHAIN32, m, 2, EXPIRY, KEYS[0].addr, 1000, B, &msg);
    att_sign(&KEYS[0], &msg, NULL, 0, sg2);              /* the EMPTY context */
    buf_free(&msg);
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg2, SIG_LEN);
    rev_inv(c, m, &d, KEYS[0].addr, "a signature under the empty context: refused");
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN - 1,
            sg, SIG_LEN);
    rev_tx(c, S_OUT, m, 0, &d, "MLDSA87BadLength()", NULL, 0, "pk one byte short reverts");
    buf_free(&d);
    data_ap(&d, "approve" AP_ARGS, 2, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk, PK_LEN,
            sg, SIG_LEN - 1);
    rev_tx(c, S_OUT, m, 0, &d, "MLDSA87BadLength()", NULL, 0, "sig one byte short reverts");
    buf_free(&d);
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(2)), 0,
            "the signature faults left nonce 2 unused");

    /* ── raw verify / requireSigner ── */
    {
        enum { MAXN = MSG_MAX + 1 };
        uint8_t *big = malloc(MAXN);
        uint8_t zpk[PK_LEN], zsg[SIG_LEN];
        buf_t bm;
        if (!big) fatal("oom");
        memset(zpk, 0, sizeof(zpk));
        memset(zsg, 0, sizeof(zsg));
        for (size_t i = 0; i < MAXN; i++) big[i] = (uint8_t)(i * 7u + 3u);

        {
            enc_t e = E0();
            enc_bytes(&e, zpk, PK_LEN);
            enc_bytes(&e, zsg, SIG_LEN);
            enc_bytes(&e, big, MAXN);
            mk_call(&bm, "verifyRaw(bytes,bytes,bytes)", e);
            rev_tx(c, S_OUT, m, 0, &bm, "MLDSA87MessageTooLong(uint256)", ARGS(U(MAXN)),
                   "a 65 537-byte message reverts before the call");
            buf_free(&bm);
        }
        {
            buf_t big_msg;
            memset(&big_msg, 0, sizeof(big_msg));
            buf_put(&big_msg, big, MSG_MAX);
            att_sign_ok(&KEYS[1], &big_msg, sg);
            enc_t e = E0();
            enc_bytes(&e, KEYS[1].pk, PK_LEN);
            enc_bytes(&e, sg, SIG_LEN);
            enc_bytes(&e, big, MSG_MAX);
            view_at(c, m, "verifyRaw(bytes,bytes,bytes)", e, 0, w, "verify 65536 ok");
            ck_u64(c, w, 1, "a signature over a 65 536-byte message verifies (ok)");
            enc_t e2 = E0();
            enc_bytes(&e2, KEYS[1].pk, PK_LEN);
            enc_bytes(&e2, sg, SIG_LEN);
            enc_bytes(&e2, big, MSG_MAX);
            view_at(c, m, "verifyRaw(bytes,bytes,bytes)", e2, 1, w, "verify 65536 signer");
            ck_addr(c, w, KEYS[1].addr, "... and returns the signer's 32-byte address");
            buf_free(&big_msg);
        }
        free(big);
    }
    {
        buf_t rd;
        enc_t e = E0();
        enc_word(&e, ZERO);
        enc_bytes(&e, KEYS[0].pk, PK_LEN);
        enc_bytes(&e, sg, SIG_LEN);
        enc_bytes(&e, DATA5, 5);
        mk_call(&rd, "requireSignerRaw(address,bytes,bytes,bytes)", e);
        rev_tx(c, S_OUT, m, 0, &rd, "MLDSA87ZeroSigner()", NULL, 0,
               "a zero expected signer reverts MLDSA87ZeroSigner");
        buf_free(&rd);
    }
    {
        /* requireSigner passes for the right signer and refuses another */
        buf_t body, rd;
        memset(&body, 0, sizeof(body));
        buf_put(&body, DATA5, 5);
        att_sign_ok(&KEYS[2], &body, sg2);
        for (int who = 0; who < 2; who++) {
            enc_t e = E0();
            enc_word(&e, who ? KEYS[1].addr : KEYS[2].addr);
            enc_bytes(&e, KEYS[2].pk, PK_LEN);
            enc_bytes(&e, sg2, SIG_LEN);
            enc_bytes(&e, DATA5, 5);
            mk_call(&rd, "requireSignerRaw(address,bytes,bytes,bytes)", e);
            if (who) rev_tx(c, S_OUT, m, 0, &rd, INVALID_SIG, ARGS(KEYS[1].addr),
                            "requireSigner: another expected signer refused");
            else ok_tx(c, S_OUT, m, 0, &rd, NULL, "requireSigner: the right signer passes");
            buf_free(&rd);
        }
        buf_free(&body);
    }

    /* ── decode pins of the pinned compiler (consumeRaw: any message) ── */
    {
        static const uint8_t NOPK[1] = { 0 };
        buf_t rd, hm;
        enc_t e;
        memset(&hm, 0, sizeof(hm));
        /* 223 bytes: AttestationHeaderMismatch (not an empty revert) */
        {
            uint8_t z223[223];
            memset(z223, 0, sizeof(z223));
            e = E0();
            enc_word(&e, atype);
            enc_word(&e, U(100));
            enc_word(&e, U(EXPIRY));
            enc_word(&e, KEYS[0].addr);
            enc_bytes(&e, NOPK, 0);
            enc_bytes(&e, NOPK, 0);
            enc_bytes(&e, z223, sizeof(z223));
            mk_call(&rd, "consumeRaw(bytes32,uint256,uint64,address,bytes,bytes,bytes)", e);
            rev_tx(c, S_OUT, m, 0, &rd, HDR_MISMATCH, NULL, 0,
                   "a 223-byte message reverts AttestationHeaderMismatch");
            buf_free(&rd);
        }
        /* an expiry word with bit 64 set: AttestationHeaderMismatch, with data */
        bld_approve(c, B_APPROVE_MSG, m, CHAIN32, m, 101, EXPIRY, KEYS[0].addr, 1, B, &hm);
        hm.b[160 + 23] = 0x01;                    /* word 5 = expiry; byte 23 = bit 64 */
        e = E0();
        enc_word(&e, atype);
        enc_word(&e, U(101));
        enc_word(&e, U(EXPIRY));
        enc_word(&e, KEYS[0].addr);
        enc_bytes(&e, NOPK, 0);
        enc_bytes(&e, NOPK, 0);
        enc_bytes(&e, hm.b, hm.n);
        mk_call(&rd, "consumeRaw(bytes32,uint256,uint64,address,bytes,bytes,bytes)", e);
        rev_tx(c, S_OUT, m, 0, &rd, HDR_MISMATCH, NULL, 0,
               "an expiry word with bit 64 set reverts AttestationHeaderMismatch (with data)");
        buf_free(&rd);
        buf_free(&hm);
        /* a header followed by extra trailing bytes decodes (signed, consumed) */
        bld_approve(c, B_APPROVE_MSG, m, CHAIN32, m, 102, EXPIRY, KEYS[0].addr, 1, B, &hm);
        buf_put(&hm, DATA5, 5);
        att_sign_ok(&KEYS[0], &hm, sg2);
        e = E0();
        enc_word(&e, atype);
        enc_word(&e, U(102));
        enc_word(&e, U(EXPIRY));
        enc_word(&e, KEYS[0].addr);
        enc_bytes(&e, KEYS[0].pk, PK_LEN);
        enc_bytes(&e, sg2, SIG_LEN);
        enc_bytes(&e, hm.b, hm.n);
        mk_call(&rd, "consumeRaw(bytes32,uint256,uint64,address,bytes,bytes,bytes)", e);
        ok_tx(c, S_OUT, m, 0, &rd, NULL, "a header followed by trailing bytes is accepted");
        buf_free(&rd);
        buf_free(&hm);
        ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(102)), 1,
                "... and consumed");
    }

    /* ── the misordered header ── */
    bld_approve(c, B_MISORD_MSG, m, CHAIN32, m, 4, EXPIRY, KEYS[0].addr, 1000, B, &msg);
    att_sign_ok(&KEYS[0], &msg, sg);
    buf_free(&msg);
    data_ap(&d, "approveMisordered" AP_ARGS, 4, EXPIRY, KEYS[0].addr, 1000, B, KEYS[0].pk,
            PK_LEN, sg, SIG_LEN);
    rev_tx(c, S_OUT, m, 0, &d, HDR_MISMATCH, NULL, 0,
           "a misordered header is refused even with a valid signature over it");
    buf_free(&d);
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(4)), 0,
            "the misordered attempt left nonce 4 unused");

    /* ── the header-only negative: the relayer chooses the unsigned values ── */
    {
        enc_t e = E0();
        enc_word(&e, CHAIN32);
        enc_word(&e, m);
        enc_word(&e, U(5));
        enc_word(&e, U(EXPIRY));
        enc_word(&e, KEYS[0].addr);
        view_bytes(c, m, "headerOnlyMessage(uint256,address,uint256,uint64,address)", e,
                   &msg, "headerOnlyMessage");
    }
    ck(c, msg.n == 224, "the header-only message is exactly the 224-byte header");
    att_sign_ok(&KEYS[0], &msg, sg);
    buf_free(&msg);
    data_ap(&d, "approveHeaderOnly" AP_ARGS, 5, EXPIRY, KEYS[0].addr, 777777, C, KEYS[0].pk,
            PK_LEN, sg, SIG_LEN);
    ok_tx(c, S_D, m, 0, &d, NULL,
          "header-only: the relayer picks amount and recipient and it is accepted");
    buf_free(&d);
    ck_bool(c, m, "allowance(address)", E(C), 777777,
            "header-only: the UNSIGNED values took effect (the README rule, negative example)");

    /* ── cancel and namespaces ── */
    if (call_ok(c, S_SIG1, m, 0, "cancelAttestationNonce(uint256)", E(U(50)), &r,
                "signer 1 cancels nonce 50")) {
        ck_log(c, &r, m, "AttestationNonceCancelled(address,uint256)",
               ARGS(KEYS[1].addr, U(50)), "AttestationNonceCancelled");
        evm_tx_result_free(&r);
    }
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[1].addr, U(50)), 1,
            "nonce 50 of signer 1 is used");
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(50)), 0,
            "nonce 50 of signer 0 is untouched (namespaces are independent)");
    ap_sign(c, m, CHAIN32, 50, EXPIRY, &KEYS[1], KEYS[1].addr, 5, B, sg);
    data_ap(&d, "approve" AP_ARGS, 50, EXPIRY, KEYS[1].addr, 5, B, KEYS[1].pk, PK_LEN, sg,
            SIG_LEN);
    rev_used(c, m, &d, KEYS[1].addr, 50, "a cancelled nonce: the attestation is refused");
    call_rev(c, S_SIG1, m, 0, "cancelAttestationNonce(uint256)", E(U(50)), NONCE_USED,
             ARGS(KEYS[1].addr, U(50)), "cancelling twice is refused");
    call_rev(c, S_SIG0, m, 0, "cancelAttestationNonce(uint256)", E(U(1)), NONCE_USED,
             ARGS(KEYS[0].addr, U(1)), "cancelling a USED nonce is refused");
    call_ok(c, S_D, m, 0, "cancelAttestationNonce(uint256)", E(U(51)), NULL,
            "an outsider cancels its own nonce 51");
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(D, U(51)), 1,
            "the outsider's nonce 51 is used");
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(51)), 0,
            "... and signer 0's nonce 51 is untouched");
    ap_sign(c, m, CHAIN32, 50, EXPIRY, &KEYS[0], KEYS[0].addr, 5, B, sg);
    data_ap(&d, "approve" AP_ARGS, 50, EXPIRY, KEYS[0].addr, 5, B, KEYS[0].pk, PK_LEN, sg,
            SIG_LEN);
    ok_tx(c, S_OUT, m, 0, &d, NULL, "signer 0's nonce 50 still works after signer 1's cancel");
    buf_free(&d);

    /* ── the 2-of-3 action: a signer counts once per proposal ── */
    {
        enc_t e = E0();
        enc_word(&e, B);
        enc_word(&e, U(5));
        enc_bytes(&e, DATA5, 5);
        view(c, m, "proposalId(address,uint256,bytes)", e, pid, "proposalId");
    }
    bld_submit(c, m, 60, EXPIRY, KEYS[0].addr, B, 5, DATA5, 5, &msg);
    att_sign_ok(&KEYS[0], &msg, sg);
    buf_free(&msg);
    data_submit(&d, 60, EXPIRY, KEYS[0].addr, B, 5, DATA5, 5, &KEYS[0], sg);
    if (ok_tx(c, S_OUT, m, 0, &d, &r, "signer 0 submits (nonce 60)")) {
        ck_log(c, &r, m, "Counted(bytes32,address,uint256)", ARGS(pid, KEYS[0].addr),
               "Counted");
        evm_tx_result_free(&r);
    }
    buf_free(&d);
    ck_bool(c, m, "approvals(bytes32)", E(pid), 1, "one approval");
    bld_submit(c, m, 61, EXPIRY, KEYS[0].addr, B, 5, DATA5, 5, &msg);
    att_sign_ok(&KEYS[0], &msg, sg);
    buf_free(&msg);
    data_submit(&d, 61, EXPIRY, KEYS[0].addr, B, 5, DATA5, 5, &KEYS[0], sg);
    ok_tx(c, S_OUT, m, 0, &d, NULL, "signer 0 submits the same proposal under nonce 61");
    buf_free(&d);
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(61)), 1,
            "nonce 61 was consumed");
    ck_bool(c, m, "approvals(bytes32)", E(pid), 1,
            "the same signer under two nonces is still ONE approval");
    ck_bool(c, m, "executed(bytes32)", E(pid), 0, "not executed at one distinct signer");
    bld_submit(c, m, 60, EXPIRY, KEYS[1].addr, B, 5, DATA5, 5, &msg);
    att_sign_ok(&KEYS[1], &msg, sg);
    buf_free(&msg);
    data_submit(&d, 60, EXPIRY, KEYS[1].addr, B, 5, DATA5, 5, &KEYS[1], sg);
    if (ok_tx(c, S_OUT, m, 0, &d, &r, "signer 1 submits (nonce 60 of its own namespace)")) {
        ck_log(c, &r, m, "Executed(bytes32)", ARGS(pid), "Executed");
        evm_tx_result_free(&r);
    }
    buf_free(&d);
    ck_bool(c, m, "approvals(bytes32)", E(pid), 2, "two distinct signers");
    ck_bool(c, m, "executed(bytes32)", E(pid), 1, "executed at the second distinct signer");
    bld_submit(c, m, 62, EXPIRY, KEYS[3].addr, B, 5, DATA5, 5, &msg);
    att_sign_ok(&KEYS[3], &msg, sg);
    buf_free(&msg);
    data_submit(&d, 62, EXPIRY, KEYS[3].addr, B, 5, DATA5, 5, &KEYS[3], sg);
    rev_tx(c, S_OUT, m, 0, &d, "MockNotSigner(address)", ARGS(KEYS[3].addr),
           "a valid attestation by a key outside the set is refused by the consumer");
    buf_free(&d);
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[3].addr, U(62)), 0,
            "... and its nonce mark rolled back");
    ck_bool(c, m, "approvals(bytes32)", E(pid), 2, "approvals unchanged by the outsider");

    /* ── re-entry with the same attestation ── */
    if (deploy(c, S_A, K_ACTOR, E0(), 0, x, NULL, "deploy MockActor") != 0) return;
    {
        enc_t e = E0();
        enc_word(&e, CHAIN32);
        enc_word(&e, m);
        enc_word(&e, U(70));
        enc_word(&e, U(EXPIRY));
        enc_word(&e, KEYS[0].addr);
        enc_word(&e, x);
        view_bytes(c, m, "notifyMessage(uint256,address,uint256,uint64,address,address)", e,
                   &msg, "notifyMessage");
    }
    att_sign_ok(&KEYS[0], &msg, sg);
    buf_free(&msg);
    {
        enc_t e = E0();
        enc_word(&e, U(70));
        enc_word(&e, U(EXPIRY));
        enc_word(&e, KEYS[0].addr);
        enc_word(&e, x);
        enc_bytes(&e, KEYS[0].pk, PK_LEN);
        enc_bytes(&e, sg, SIG_LEN);
        mk_call(&d, "notify(uint256,uint64,address,address,bytes,bytes)", e);
    }
    actor_mode(c, x, MODE_REENTER, m, &d);           /* hook() replays this very call */
    ok_tx(c, S_OUT, m, 0, &d, NULL, "notify: consume, then the target hook runs");
    buf_free(&d);
    ck_bool(c, m, "notified()", E0(), 1, "the effect ran exactly once");
    ck_bool(c, x, "reAttempts()", E0(), 1, "the target re-entered once");
    ck_bool(c, x, "reOk()", E0(), 0, "the re-entry failed");
    view(c, x, "reErr()", E0(), w, "reErr()");
    ck_sel(c, w, NONCE_USED, "the re-entry was refused with AttestationNonceUsed");

    /* ── a revert after the consume rolls the nonce mark back ── */
    for (int fail = 1; fail >= 0; fail--) {
        enc_t e = E0();
        enc_word(&e, CHAIN32);
        enc_word(&e, m);
        enc_word(&e, U(80));
        enc_word(&e, U(EXPIRY));
        enc_word(&e, KEYS[0].addr);
        enc_word(&e, U(9));
        enc_word(&e, U((uint64_t)fail));
        view_bytes(c, m, "guardedMessage(uint256,address,uint256,uint64,address,uint256,bool)",
                   e, &msg, "guardedMessage");
        att_sign_ok(&KEYS[0], &msg, sg);
        buf_free(&msg);
        e = E0();
        enc_word(&e, U(80));
        enc_word(&e, U(EXPIRY));
        enc_word(&e, KEYS[0].addr);
        enc_word(&e, U(9));
        enc_word(&e, U((uint64_t)fail));
        enc_bytes(&e, KEYS[0].pk, PK_LEN);
        enc_bytes(&e, sg, SIG_LEN);
        mk_call(&d, "guarded(uint256,uint64,address,uint256,bool,bytes,bytes)", e);
        if (fail) {
            rev_tx(c, S_OUT, m, 0, &d, "MockEffectFailed()", NULL, 0,
                   "guarded: the signed flag makes the effect revert");
            ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(80)),
                    0, "the nonce mark rolled back with the revert");
            ck_bool(c, m, "guardedRuns()", E0(), 0, "the effect's write rolled back too");
        } else {
            ok_tx(c, S_OUT, m, 0, &d, NULL,
                  "the same nonce works for another signed message after the rollback");
            ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(80)),
                    1, "nonce 80 is now used");
            ck_bool(c, m, "guardedRuns()", E0(), 1, "the effect ran once");
        }
        buf_free(&d);
    }

    /* ── a starved precompile ── */
    scen_starved(c, m);

    /* ── expiry: accepted AT block.timestamp == expiry, refused one second later ── */
    ap_sign(c, m, CHAIN32, 95, T0, &KEYS[0], KEYS[0].addr, 1, B, sg2);       /* for later */
    ap_sign(c, m, CHAIN32, 96, T0, &KEYS[0], KEYS[0].addr, 1, B, sg);
    data_ap(&d, "approve" AP_ARGS, 96, T0, KEYS[0].addr, 1, B, KEYS[0].pk, PK_LEN, sg,
            SIG_LEN);
    ok_tx(c, S_OUT, m, 0, &d, NULL, "accepted at block.timestamp == expiry");
    buf_free(&d);
    ap_sign(c, m, CHAIN32, 97, T0 - 1, &KEYS[0], KEYS[0].addr, 1, B, sg);
    data_ap(&d, "approve" AP_ARGS, 97, T0 - 1, KEYS[0].addr, 1, B, KEYS[0].pk, PK_LEN, sg,
            SIG_LEN);
    rev_tx(c, S_OUT, m, 0, &d, "AttestationExpired(uint64)", ARGS(U(T0 - 1)),
           "an expiry in the past is refused");
    buf_free(&d);
    at_time(c, T0 + 1);
    data_ap(&d, "approve" AP_ARGS, 95, T0, KEYS[0].addr, 1, B, KEYS[0].pk, PK_LEN, sg2,
            SIG_LEN);
    rev_tx(c, S_OUT, m, 0, &d, "AttestationExpired(uint64)", ARGS(U(T0)),
           "refused at expiry + 1 (a valid, unused attestation)");
    buf_free(&d);
    ck_bool(c, m, "isAttestationNonceUsed(address,uint256)", E(KEYS[0].addr, U(95)), 0,
            "the expired attestation's nonce stayed unused");
}

/* ── deployed code = committed runtime ─────────────────────────────────── */

static void post_code(ctx_t *c)
{
    for (size_t i = 0; i < c->ndep; i++) {
        probe_t p;
        char m[160];
        const blob_t *rt = &c->runtime[c->dep_kind[i]];
        probe(c, &p, c->dep_addr[i], NULL);
        int ok = p.code_found && p.code_len == rt->n && memcmp(p.code, rt->b, rt->n) == 0;
        free(p.code);
        snprintf(m, sizeof(m), "deployed code of %s #%u = the committed runtime.hex",
                 NAMES[c->dep_kind[i]], (unsigned)i);
        ck(c, ok, m);
    }
}

static void run_config(ctx_t *c)
{
    scen_ownable(c);
    scen_access(c);
    scen_guard(c);
    scen_timelock(c);
    scen_vault(c);
    scen_escrow(c);
    scen_ticket_mock(c);
    scen_mldsa_off(c);
    post_code(c);
}

/* The second engine state of a configuration: mldsa_precompile = 1. */
static void run_config_mldsa(ctx_t *c)
{
    scen_mldsa(c);
    post_code(c);
}

int main(int argc, char **argv)
{
    static const char *const CFGS[2] = { "default", "optimize" };
    const char *dir = argc > 1 ? argv[1] : CONTRACTS_OUT;
    int failed = 0;

    g_dir = dir;
    init_inputs();
    init_keys();
    if (self_check_rules() != 0) failed = 1;
    fprintf(stderr, "bytecode: %s\n", dir);
    for (int i = 0; i < 2; i++) {
        for (int mldsa = 0; mldsa < 2; mldsa++) {
            ctx_t *c = calloc(1, sizeof(*c));
            if (!c) fatal("oom");
            if (ctx_open(c, dir, CFGS[i], mldsa) == 0) {
                if (mldsa) run_config_mldsa(c);
                else run_config(c);
            }
            fprintf(stderr, "config %-9s mldsa_precompile %d: %u passed, %u failed\n",
                    CFGS[i], mldsa, c->pass, c->fail);
            if (c->fail || c->pass == 0) failed = 1;
            ctx_close(c);
            free(c);
        }
    }
    if (failed) {
        fprintf(stderr, "test_contract_lib: FAILED\n");
        return 1;
    }
    fprintf(stderr, "test_contract_lib: all configurations passed\n");
    return 0;
}
