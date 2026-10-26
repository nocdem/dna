/**
 * Nodus — the nodus-light PROGRAM's start-up / trust-root paths
 * (nodus/tools/nodus-light.c: root_pick, root_auto,
 * auto_construct_retryable and the construction that follows them),
 * light client package L9, 2026-10-19. The program source is INCLUDED
 * (NODUS_LIGHT_NO_MAIN) so its static functions are called as they are;
 * the providers are replaced by mocks over REAL signed light blocks and
 * the store is the program's own SQLite light store (store_open) in a
 * temporary directory.
 *
 * Governing: docs/plans/decisions/2026-10-16-kurultay-25-summary.md —
 * K25-12 (the automatic root: ≥ 2 answers with the same header hash →
 * root; fewer → retry; any two different hashes → stop, no majority),
 * K25-10 (a locked store never takes a new root), K25-2 (48 h), K25-11
 * (a node added by the refresh is never asked for the root), item 9 / D20.
 *
 * ── WHAT IT PROVES ─────────────────────────────────────────────────────
 *   · AGREE: three pinned nodes holding the same chain give the root
 *     (latest − 2, its header hash) with three answers; the light client
 *     is then constructed over it exactly as cmd_run builds it, and the
 *     store's latest block is that root;
 *   · DISAGREE: two validly signed blocks at the target from two nodes
 *     give LIGHT_AUTO_DISAGREE even when the other two answers already
 *     agree (no majority is taken), and nothing is stored;
 *   · SHORT: one answer is LIGHT_AUTO_SHORT, nothing stored; a second
 *     attempt with two answering nodes takes the root (the retry
 *     recovers) and the client is constructed;
 *   · EXPIRED: a stored block whose time + 48 h is not after `now` makes
 *     root_pick choose the automatic root (the boundary exactly as the
 *     reference's HeaderExpired: expiry == now is expired; 1 ns earlier
 *     resumes from the store); the construction then replaces the root —
 *     a stored block the primary does NOT confirm is removed through
 *     confirm_reroot, one it confirms is kept — and the store's latest
 *     block becomes the new target either way;
 *   · LOCKED: an uncleared attack record in the store makes root_pick
 *     answer LIGHT_ROOT_STORE (not the automatic root) over an expired
 *     block; the client built from the store comes up locked, and the
 *     automatic construction would be refused with ATTACK_LOCKED; the
 *     stored block is unchanged;
 *   · PINNED ONLY: a node in a slot ≥ the pinned count (the K25-11
 *     refresh's slots) is never asked by root_auto — neither as the
 *     primary nor at the target (its call counter stays 0, and the
 *     outcome is the one without it);
 *   · auto_construct_retryable: INIT_AGREEMENT_SHORT and PROVIDER with
 *     NO_RESPONSE / HEIGHT_TOO_HIGH are retried; LIGHT_BLOCK_NOT_FOUND,
 *     another refusal and a local fault are not;
 *   · light_compat_judge (update-required warning, design
 *     docs/plans/2026-10-20-update-required-warning-design.md §1 B): the
 *     log line is due once per distinct (outcome, generation, next
 *     generation, next height), never for an OK answer, and again when a
 *     state comes back after an OK answer. The dnac_ruleset_info call
 *     around it (light_compat_check) is not driven.
 *
 * ── WHAT IT REQUIRES ───────────────────────────────────────────────────
 * A default build (the target includes nodus/tools/ for the program
 * source). No compile flags, no environment variables, no network, NO
 * WALL CLOCK: root_pick's clock is the seam root_pick_at with a fixed
 * clock, every block time is a fixed value after 2006-01-02T15:04:05Z,
 * and keys come from qgp_dsa87_keypair_derand with fixed seeds.
 *
 * ── WHAT IT LEAVES BEHIND ──────────────────────────────────────────────
 * Nothing on success: each case makes a temporary directory
 * `test_nodus_light.XXXXXX` in the working directory holding light.db,
 * and removes it (qgp_platform_rmdir_recursive). A crash mid-run can
 * leave one behind.
 *
 * ── HOW IT CAN LIE ─────────────────────────────────────────────────────
 *  1. cmd_run itself is NOT driven: it connects real sessions (net_init,
 *     net_connect) and sleeps between attempts. The test calls the same
 *     functions cmd_run calls, in its order, and copies the construction
 *     cmd_run performs after LIGHT_AUTO_OK (the trust options and the
 *     four caps of nodus-light.c, confirm_reroot with is_auto = true,
 *     cmt_light_client_new over net.primary / net.witnesses) — a change
 *     to cmd_run's own sequence is not seen here. The DISAGREE exit
 *     (cmd_run: `if (arc == LIGHT_AUTO_DISAGREE) goto done;`, ret 1) was
 *     read, not executed.
 *  2. The network is bypassed in exactly one place: net_slot_ready reads
 *     nodus_client_is_ready, which reads `client->state` only
 *     (nodus_client.c); a "connected" slot here has `started[i] = true`
 *     and `clients[i].state = NODUS_CLIENT_READY` with no session behind
 *     it, and its provider table is the mock's. The pinned provider over
 *     dnac_light_block (nodus_light_provider.c, its decode and its
 *     RATE_LIMITED → NO_RESPONSE mapping) is NOT exercised.
 *  3. THE MOCK DOES NOT VALIDATE (as in test_cmt_light_client.c): it
 *     returns the block it holds; the light client's own checks judge it.
 *  4. ML-DSA-87 signing is HEDGED; header hashes depend only on header
 *     fields, so the fork is a different header (another app hash), not a
 *     different signature.
 *
 * @file test_nodus_light.c
 */

#define NODUS_LIGHT_NO_MAIN
#include "nodus-light.c"

#include "dnac/cmt_validator_set.h"
#include "dnac/cmt_vote.h"
#include "dnac/cmt_tmhash.h"
#include "crypto/sign/qgp_dilithium.h"

#include <unistd.h>

static int g_checks = 0;

/* A row: on failure print and leave through `out`. */
#define T(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); \
        goto out; \
    } \
    g_checks++; \
} while (0)

#define NKEYS  4
#define CHAIN_LEN 7          /* heights 1..7: latest 7 → target 5      */
#define TARGET (CHAIN_LEN - NODUS_LIGHT_AUTO_ROOT_BELOW_TIP)

#define SECOND ((int64_t)1000000000)
#define MINUTE (60 * SECOND)
#define HOUR   (60 * MINUTE)

/* client_test.go:32 — bTime = 2006-01-02T15:04:05Z = 1136214245 s. */
#define BTIME_SECONDS ((int64_t)1136214245)
/* A vote stamp inside no checked relation (helpers_test.go:111). */
#define VOTE_SECONDS  ((int64_t)1700000000)

/* The chain id: 32 raw bytes, as nodus-light passes it
 * (NODUS_LIGHT_CHAIN_ID_LEN) to the store prefix and the client. */
static uint8_t g_chain[NODUS_LIGHT_CHAIN_ID_LEN];

static uint8_t g_pk[NKEYS][QGP_DSA87_PUBLICKEYBYTES];
static uint8_t g_sk[NKEYS][QGP_DSA87_SECRETKEYBYTES];
static uint8_t g_addr[NKEYS][CMT_ADDRESS_SIZE];

static cmt_valset_scratch_t  *g_scratch;
static cmt_light_block_buf_t *g_buf;     /* scratch for root_pick / _auto */
static cmt_light_block_buf_t *g_out;     /* store reads                   */

typedef struct {
    cmt_validator_t     storage[NKEYS];
    cmt_validator_set_t vs;
} tvals_t;

typedef struct {
    cmt_header_t        h;
    cmt_commit_sig_t    sigs[NKEYS];
    cmt_commit_t        c;
    cmt_signed_header_t sh;
} tsh_t;

typedef struct {
    tvals_t vals;
    tsh_t   chain[CHAIN_LEN + 1];  /* index = height                      */
    tsh_t   fork;                  /* another valid block at TARGET       */
    tsh_t   alt1;                  /* another valid block at height 1     */
} tfix_t;

static tfix_t *F;

/* ══ the fixed clock (root_pick_at's seam) ═══════════════════════════ */

static cmt_time_t g_now;
static unsigned   g_clock_calls;

static int fixed_now(cmt_time_t *out)
{
    g_clock_calls++;
    *out = g_now;
    return 0;
}

/* ══ fixtures (test_cmt_light_client.c's, minimum copy) ══════════════ */

static cmt_time_t t_at(int64_t ns_after_btime)
{
    cmt_time_t b;

    b.seconds = BTIME_SECONDS;
    b.nanos   = 0;
    return cmt_time_add_ns(b, ns_after_btime);
}

static void pat(uint8_t *dst, size_t n, uint8_t seed)
{
    for (size_t i = 0; i < n; i++) {
        dst[i] = (uint8_t)((seed + 7u * (unsigned)i) & 0xFFu);
    }
}

static int build_keys(void)
{
    uint8_t seed[32];

    for (int i = 0; i < NKEYS; i++) {
        memset(seed, (uint8_t)(0x61 + i), sizeof(seed));
        if (qgp_dsa87_keypair_derand(g_pk[i], g_sk[i], seed) != 0 ||
            cmt_pubkey_address(g_pk[i], g_addr[i]) != CMT_OK) {
            fprintf(stderr, "key %d failed\n", i);
            return 1;
        }
    }
    return 0;
}

static int key_of_address(const uint8_t *addr, size_t len)
{
    if (len != (size_t)CMT_ADDRESS_SIZE) return -1;
    for (int i = 0; i < NKEYS; i++) {
        if (memcmp(g_addr[i], addr, CMT_ADDRESS_SIZE) == 0) return i;
    }
    return -1;
}

/* Four keys, power 10 each. */
static int make_vals(tvals_t *out)
{
    cmt_validator_t     list[NKEYS];
    cmt_pb_public_key_t pk;

    for (int i = 0; i < NKEYS; i++) {
        memset(&pk, 0, sizeof(pk));
        pk.present = true;
        memcpy(pk.key, g_pk[i], QGP_DSA87_PUBLICKEYBYTES);
        if (cmt_validator_new(&pk, 10, &list[i]) != CMT_OK) return 1;
    }
    if (cmt_validator_set_init(&out->vs, out->storage, NKEYS) != CMT_OK ||
        cmt_validator_set_new(&out->vs, list, NKEYS, g_scratch) != CMT_OK) {
        return 1;
    }
    return 0;
}

static int vals_hash(cmt_validator_set_t *vs, uint8_t out[CMT_TMHASH_SIZE])
{
    uint8_t           *scratch;
    cmt_merkle_item_t  items[NKEYS];
    int                rc;

    scratch = (uint8_t *)malloc(NKEYS * (size_t)CMT_VALIDATOR_BYTES_MAX);
    if (scratch == NULL) return 1;
    rc = cmt_validator_set_hash(vs, scratch,
                                NKEYS * (size_t)CMT_VALIDATOR_BYTES_MAX,
                                items, NKEYS, out);
    free(scratch);
    return rc == CMT_OK ? 0 : 1;
}

static int sign_entry(cmt_commit_t *c, cmt_validator_set_t *vs, size_t idx)
{
    uint8_t           sb[CMT_VOTE_SIGN_BYTES_MAX];
    size_t            sb_len;
    size_t            siglen;
    cmt_commit_sig_t *cs = &c->signatures[idx];
    int               k;

    memset(cs, 0, sizeof(*cs));
    cs->block_id_flag = (int32_t)CMT_BLOCK_ID_FLAG_COMMIT;
    memcpy(cs->validator_address, vs->validators[idx].address,
           CMT_ADDRESS_SIZE);
    cs->validator_address_len = CMT_ADDRESS_SIZE;
    cs->timestamp.seconds     = VOTE_SECONDS;
    cs->timestamp.nanos       = 0;

    k = key_of_address(vs->validators[idx].address,
                       vs->validators[idx].address_len);
    if (k < 0 ||
        cmt_commit_vote_sign_bytes(c, g_chain, sizeof(g_chain), (int32_t)idx,
                                   sb, sizeof(sb), &sb_len) != CMT_OK ||
        qgp_dsa87_sign(cs->signature, &siglen, sb, sb_len, g_sk[k]) != 0) {
        fprintf(stderr, "sign entry %zu failed\n", idx);
        return 1;
    }
    cs->signature_len = siglen;
    return 0;
}

/* helpers_test.go:135-177 GenSignedHeader(LastBlockID), every key
 * signing; `last_hash` NULL = no LastBlockID. */
static int gen_sh(tsh_t *out, int64_t height, cmt_time_t btime,
                  const uint8_t *last_hash, const char *app)
{
    cmt_header_t *h = &out->h;

    cmt_pb_header_init(h);
    h->version.block = CMT_BLOCK_PROTOCOL;
    h->version.app   = 0;
    memcpy(h->chain_id, g_chain, sizeof(g_chain));
    h->chain_id_len  = sizeof(g_chain);
    h->height        = height;
    h->time          = btime;
    if (last_hash != NULL) {
        memcpy(h->last_block_id.hash, last_hash, CMT_TMHASH_SIZE);
        h->last_block_id.hash_len = CMT_TMHASH_SIZE;
    }
    if (vals_hash(&F->vals.vs, h->validators_hash) != 0 ||
        vals_hash(&F->vals.vs, h->next_validators_hash) != 0 ||
        cmt_data_hash(NULL, h->data_hash) != CMT_OK ||
        cmt_tmhash_sum((const uint8_t *)app, strlen(app),
                       h->app_hash) != CMT_OK ||
        cmt_tmhash_sum((const uint8_t *)"cons_hash", strlen("cons_hash"),
                       h->consensus_hash) != CMT_OK ||
        cmt_tmhash_sum((const uint8_t *)"results_hash",
                       strlen("results_hash"),
                       h->last_results_hash) != CMT_OK) {
        return 1;
    }
    h->validators_hash_len      = CMT_TMHASH_SIZE;
    h->next_validators_hash_len = CMT_TMHASH_SIZE;
    h->data_hash_len            = CMT_TMHASH_SIZE;
    h->app_hash_len             = CMT_TMHASH_SIZE;
    h->consensus_hash_len       = CMT_TMHASH_SIZE;
    h->last_results_hash_len    = CMT_TMHASH_SIZE;
    memcpy(h->proposer_address, F->vals.vs.validators[0].address,
           CMT_ADDRESS_SIZE);
    h->proposer_address_len = CMT_ADDRESS_SIZE;

    cmt_pb_commit_init(&out->c);
    out->c.height         = height;
    out->c.round          = 1;
    out->c.signatures     = out->sigs;
    out->c.signatures_cap = NKEYS;
    out->c.signatures_len = NKEYS;
    for (size_t i = 0; i < NKEYS; i++) {
        cmt_new_commit_sig_absent(&out->sigs[i]);
    }
    if (cmt_header_hash(h, out->c.block_id.hash) != CMT_OK) return 1;
    out->c.block_id.hash_len                 = CMT_TMHASH_SIZE;
    out->c.block_id.part_set_header.total    = 1u;
    pat(out->c.block_id.part_set_header.hash, CMT_TMHASH_SIZE, 0x5C);
    out->c.block_id.part_set_header.hash_len = CMT_TMHASH_SIZE;
    for (size_t i = 0; i < NKEYS; i++) {
        if (sign_entry(&out->c, &F->vals.vs, i) != 0) return 1;
    }
    out->sh.header = &out->h;
    out->sh.commit = &out->c;
    return 0;
}

static int sh_hash(const tsh_t *s, uint8_t out[CMT_TMHASH_SIZE])
{
    return cmt_header_hash(&s->h, out) == CMT_OK ? 0 : 1;
}

/* Heights 1..CHAIN_LEN at bTime + h minutes, each linked to its parent;
 * `fork` is a second valid block at TARGET on the same parent (another
 * app hash); `alt1` a second valid height-1 block. */
static int build_fixture(void)
{
    uint8_t hh[CMT_TMHASH_SIZE];

    if (make_vals(&F->vals) != 0) return 1;
    if (gen_sh(&F->chain[1], 1, t_at(MINUTE), NULL, "app_hash") != 0) {
        return 1;
    }
    for (int64_t h = 2; h <= CHAIN_LEN; h++) {
        if (sh_hash(&F->chain[h - 1], hh) != 0 ||
            gen_sh(&F->chain[h], h, t_at(h * MINUTE), hh, "app_hash") != 0) {
            return 1;
        }
    }
    if (sh_hash(&F->chain[TARGET - 1], hh) != 0 ||
        gen_sh(&F->fork, TARGET, t_at(TARGET * MINUTE), hh,
               "app_hash_fork") != 0 ||
        gen_sh(&F->alt1, 1, t_at(MINUTE), NULL, "app_hash_alt") != 0) {
        return 1;
    }
    return 0;
}

/* ══ the mock pinned node ════════════════════════════════════════════ */

/* One node: `at[h]` is the block it holds at height h (NULL: not held).
 * `dead` answers NO_RESPONSE (an unreachable node, or one at its rate
 * limit — nodus_light_provider.h). `calls` counts light_block calls. */
typedef struct {
    const tsh_t *at[CHAIN_LEN + 1];
    int64_t      latest;
    bool         dead;
    unsigned     calls;
} tmock_t;

static void mock_chain(tmock_t *m)
{
    memset(m, 0, sizeof(*m));
    for (int64_t h = 1; h <= CHAIN_LEN; h++) m->at[h] = &F->chain[h];
    m->latest = CHAIN_LEN;
}

static int mock_chain_id(void *ctx, const uint8_t **out, size_t *out_len)
{
    if (ctx == NULL || out == NULL || out_len == NULL) return CMT_FAULT;
    *out     = g_chain;
    *out_len = sizeof(g_chain);
    return CMT_OK;
}

static void prov_err(cmt_light_provider_error_t *err, int code)
{
    if (err != NULL) {
        err->code   = code;
        err->reason = CMT_OK;
    }
}

/* Copy the held block into the caller's buffer as is (no validation). */
static int mock_copy(cmt_light_block_buf_t *out, const tsh_t *s)
{
    if (cmt_light_block_buf_reset(out) != CMT_OK) return CMT_FAULT;
    out->header               = s->h;
    out->signed_header.header = &out->header;
    out->commit                = s->c;
    out->commit.signatures     = out->sigs;
    out->commit.signatures_cap = (size_t)CMT_VALSET_MAX;
    memcpy(out->sigs, s->c.signatures,
           s->c.signatures_len * sizeof(out->sigs[0]));
    out->signed_header.commit = &out->commit;
    out->lb.signed_header     = &out->signed_header;
    if (cmt_validator_set_copy(&F->vals.vs, &out->validator_set) != CMT_OK) {
        return CMT_FAULT;
    }
    out->lb.validator_set = &out->validator_set;
    return CMT_OK;
}

static int mock_light_block(void *ctx, int64_t height,
                            cmt_light_block_buf_t *out,
                            cmt_light_provider_error_t *err)
{
    tmock_t *m = ctx;

    prov_err(err, CMT_LIGHT_PROVIDER_ERR_NONE);
    if (m == NULL || out == NULL || height < 0) return CMT_FAULT;
    m->calls++;
    (void)cmt_light_block_buf_reset(out);
    if (m->dead) {
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE);
        return CMT_REJECT;
    }
    if (height > m->latest) {
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH);
        return CMT_REJECT;
    }
    if (height == 0) height = m->latest;
    if (m->at[height] == NULL) {
        prov_err(err, CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND);
        return CMT_REJECT;
    }
    return mock_copy(out, m->at[height]);
}

static int mock_report_evidence(void *ctx, const cmt_pb_evidence_t *ev)
{
    (void)ev;
    return ctx == NULL ? CMT_FAULT : CMT_OK;
}

/* ══ the program's network table over mocks ══════════════════════════ */

#define MAX_MOCKS 4

typedef struct {
    light_node_t nodes[NODUS_LIGHT_MAX_NODES];   /* the args' table      */
    tmock_t      mocks[MAX_MOCKS];
    light_net_t  net;
    bool         net_up;
    char         dir[64];
    light_store_t st;
    bool         st_open;
} tcase_t;

/*
 * The net_init layout (every array NODUS_LIGHT_MAX_NODES slots), with no
 * nodus client initialised and no session key: slot i's provider table is
 * mock i, and a "connected" slot is `started` with its client's state
 * READY — all net_slot_ready reads (HOW IT CAN LIE 2). Pins are distinct
 * per slot: the light client counts agreement by them (item 9 R2).
 */
static int tnet_init(tcase_t *tc, size_t n)
{
    light_net_t *net = &tc->net;
    const size_t cap = NODUS_LIGHT_MAX_NODES;

    memset(net, 0, sizeof(*net));
    net->n         = n;
    net->nodes     = tc->nodes;
    memcpy(net->chain_id, g_chain, sizeof(g_chain));
    net->clients   = calloc(cap, sizeof(*net->clients));
    net->inited    = calloc(cap, sizeof(*net->inited));
    net->started   = calloc(cap, sizeof(*net->started));
    net->providers = calloc(cap, sizeof(*net->providers));
    net->tables    = calloc(cap, sizeof(*net->tables));
    net->witnesses = calloc(cap, sizeof(*net->witnesses));
    net->pending   = calloc(cap, sizeof(*net->pending));
    tc->net_up     = true;
    if (!net->clients || !net->inited || !net->started || !net->providers ||
        !net->tables || !net->witnesses || !net->pending) {
        return 1;
    }
    for (size_t i = 0; i < n; i++) {
        light_node_t *nd = &tc->nodes[i];
        memset(nd, 0, sizeof(*nd));
        snprintf(nd->label, sizeof(nd->label), "mock%u", (unsigned)i);
        snprintf(nd->host, sizeof(nd->host), "127.0.0.1");
        nd->port = (uint16_t)(14001u + 10u * (unsigned)i);
        pat(nd->pin.bytes, sizeof(nd->pin.bytes), (uint8_t)(0x10 + i));
        net->tables[i].ctx             = &tc->mocks[i];
        net->tables[i].chain_id        = mock_chain_id;
        net->tables[i].light_block     = mock_light_block;
        net->tables[i].report_evidence = mock_report_evidence;
        net->started[i]                = true;
        net->clients[i].state          = NODUS_CLIENT_READY;
    }
    return 0;
}

/* A case: `n` mock nodes, each holding the chain, connected; the
 * program's light store (store_open) in a fresh temporary directory. */
static int case_open(tcase_t *tc, size_t n)
{
    memset(tc, 0, sizeof(*tc));
    for (size_t i = 0; i < MAX_MOCKS; i++) mock_chain(&tc->mocks[i]);
    if (tnet_init(tc, n) != 0) {
        fprintf(stderr, "net layout failed\n");
        return 1;
    }
    memcpy(tc->dir, "test_nodus_light.XXXXXX",
           sizeof("test_nodus_light.XXXXXX"));
    if (mkdtemp(tc->dir) == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        tc->dir[0] = '\0';
        return 1;
    }
    if (store_open(&tc->st, tc->dir, g_chain) != 0) return 1;
    tc->st_open = true;
    return 0;
}

static void case_close(tcase_t *tc)
{
    if (tc->st_open) store_close(&tc->st);
    tc->st_open = false;
    if (tc->net_up) net_free(&tc->net);    /* no client is inited */
    tc->net_up = false;
    if (tc->dir[0] != '\0') {
        (void)qgp_platform_rmdir_recursive(tc->dir);
        tc->dir[0] = '\0';
    }
}

static int store_save_block(tcase_t *tc, const tsh_t *s)
{
    cmt_light_block_t lb;

    lb.signed_header = &s->sh;
    lb.validator_set = &F->vals.vs;
    return cmt_light_store_db_save_light_block(tc->st.db, &lb);
}

static int64_t store_last(tcase_t *tc)
{
    int64_t h = -2;

    (void)cmt_light_store_db_last_light_block_height(tc->st.db, &h);
    return h;
}

static int64_t store_first(tcase_t *tc)
{
    int64_t h = -2;

    (void)cmt_light_store_db_first_light_block_height(tc->st.db, &h);
    return h;
}

/* The stored block at `height` has the header hash of `s`. */
static bool stored_is(tcase_t *tc, int64_t height, const tsh_t *s)
{
    bool    found = false;
    uint8_t a[CMT_TMHASH_SIZE], b[CMT_TMHASH_SIZE];

    if (cmt_light_store_db_light_block(tc->st.db, height, g_out,
                                       &found) != CMT_OK || !found ||
        g_out->lb.signed_header == NULL ||
        g_out->lb.signed_header->header == NULL ||
        cmt_header_hash(g_out->lb.signed_header->header, a) != CMT_OK ||
        sh_hash(s, b) != 0) {
        return false;
    }
    return memcmp(a, b, CMT_TMHASH_SIZE) == 0;
}

static bool stored_any(tcase_t *tc, int64_t height)
{
    bool found = false;

    return cmt_light_store_db_light_block(tc->st.db, height, g_out,
                                          &found) == CMT_OK && found;
}

/* The light client options exactly as cmd_run sets them. */
static void run_opts(cmt_light_client_options_t *opts, bool *is_auto)
{
    cmt_light_client_options_default(opts);
    opts->max_trace_len       = NODUS_LIGHT_MAX_TRACE_LEN;
    opts->max_verify_steps    = NODUS_LIGHT_MAX_VERIFY_STEPS;
    opts->max_skipping_cache  = NODUS_LIGHT_MAX_SKIPPING_CACHE;
    opts->max_backwards_steps = NODUS_LIGHT_MAX_BACKWARDS_STEPS;
    opts->confirm             = confirm_reroot;
    opts->confirm_ctx         = is_auto;
}

/* cmd_run after LIGHT_AUTO_OK: cmt_light_client_new over (target, hash)
 * with net.primary / net.witnesses and the program's store (HOW IT CAN
 * LIE 1). */
static int construct_auto(tcase_t *tc, int64_t target,
                          uint8_t hash[CMT_TMHASH_SIZE],
                          cmt_light_client_t **c,
                          cmt_light_client_error_t *err)
{
    static bool                 is_auto = true;
    cmt_light_trust_options_t   trust;
    cmt_light_client_options_t  opts;

    memset(&trust, 0, sizeof(trust));
    trust.height   = target;
    trust.hash     = hash;
    trust.period   = NODUS_LIGHT_TRUSTING_PERIOD_NS;
    trust.hash_len = CMT_TMHASH_SIZE;
    run_opts(&opts, &is_auto);
    memset(err, 0, sizeof(*err));
    return cmt_light_client_new(g_chain, sizeof(g_chain), &trust,
                                &tc->net.primary, tc->net.witnesses,
                                tc->net.n_witnesses, &tc->st.store, &opts,
                                c, err);
}

/* root_pick_at as cmd_run calls root_pick: no operator root, the store's
 * last height read first. */
static int pick(tcase_t *tc, int *mode)
{
    light_args_t a;
    int64_t      last = -2;

    memset(&a, 0, sizeof(a));
    *mode = -1;
    if (cmt_light_store_db_last_light_block_height(tc->st.db,
                                                   &last) != CMT_OK) {
        return -1;
    }
    return root_pick_at(&a, &tc->st, last, g_buf, fixed_now, mode);
}

/* ══ 1. AGREE ═════════════════════════════════════════════════════════ */

/* Proves: three pinned nodes with the same block at the target give the
 * root (latest − 2, its hash, 3 answers) and the client is built over it;
 * the store then holds the root. Fails if the target, the hash, the count
 * or the construction were wrong. */
static int t_agree(void)
{
    tcase_t                  *tc = calloc(1, sizeof(*tc));
    cmt_light_client_t       *c = NULL;
    cmt_light_client_error_t  err;
    uint8_t                   hash[CMT_TMHASH_SIZE], want[CMT_TMHASH_SIZE];
    int64_t                   t = 0;
    size_t                    answers = 0;
    int                       mode;
    int                       ret = 1;

    T(tc != NULL && case_open(tc, 3) == 0, "agree: case");
    g_clock_calls = 0;
    T(pick(tc, &mode) == 0 && mode == LIGHT_ROOT_AUTO,
      "agree: an empty store takes the automatic root");
    T(g_clock_calls == 0, "agree: an empty store reads no clock");
    T(root_auto(&tc->net, tc->net.n, g_buf, &t, hash,
                &answers) == LIGHT_AUTO_OK, "agree: root_auto OK");
    T(sh_hash(&F->chain[TARGET], want) == 0 && t == TARGET &&
      memcmp(hash, want, CMT_TMHASH_SIZE) == 0,
      "agree: the root is (latest - 2, its header hash)");
    T(answers == 3, "agree: three nodes answered");
    T(tc->net.primary_idx == 0 && tc->net.n_witnesses == 2,
      "agree: the first connected node is the primary, the others witnesses");
    T(store_last(tc) == -1, "agree: root_auto itself stores nothing");
    T(construct_auto(tc, t, hash, &c, &err) == CMT_OK && c != NULL,
      "agree: the client is constructed over the root");
    T(!cmt_light_client_attack_locked(c), "agree: not locked");
    T(store_last(tc) == TARGET && stored_is(tc, TARGET, &F->chain[TARGET]),
      "agree: the store's latest block is the root");
    ret = 0;
out:
    cmt_light_client_free(c);
    if (tc != NULL) case_close(tc);
    free(tc);
    return ret;
}

/* ══ 2. DISAGREE ══════════════════════════════════════════════════════ */

/* Proves: two different validly signed blocks at the target stop the
 * start (LIGHT_AUTO_DISAGREE) even though two of the three answers agree —
 * no majority (K25-12) — and nothing is stored (cmd_run then exits 1
 * without building a client, HOW IT CAN LIE 1). Fails if a majority were
 * taken (OK) or the conflict were treated as silence (OK / SHORT). */
static int t_disagree(void)
{
    tcase_t *tc = calloc(1, sizeof(*tc));
    uint8_t  hash[CMT_TMHASH_SIZE];
    int64_t  t = 0;
    size_t   answers = 0;
    int      ret = 1;

    T(tc != NULL && case_open(tc, 3) == 0, "disagree: case");
    /* Slots 0 and 1 agree; slot 2, asked last, holds the fork (shown to
     * be a valid block at the end of this case). */
    tc->mocks[2].at[TARGET] = &F->fork;
    T(root_auto(&tc->net, tc->net.n, g_buf, &t, hash,
                &answers) == LIGHT_AUTO_DISAGREE,
      "disagree: two different blocks at the target stop the start");
    T(tc->mocks[0].calls == 2 && tc->mocks[1].calls == 1 &&
      tc->mocks[2].calls == 1, "disagree: every pinned node was asked");
    T(store_last(tc) == -1, "disagree: nothing stored");

    /* The same with the forking node first among the witnesses. */
    for (size_t i = 0; i < 3; i++) mock_chain(&tc->mocks[i]);
    tc->mocks[1].at[TARGET] = &F->fork;
    T(root_auto(&tc->net, tc->net.n, g_buf, &t, hash,
                &answers) == LIGHT_AUTO_DISAGREE,
      "disagree: order does not matter");
    T(tc->mocks[2].calls == 0,
      "disagree: the stop comes at the first conflicting answer");
    T(store_last(tc) == -1, "disagree: still nothing stored");

    /* The fork is a valid block in its own right: when every node holds
     * it, it is the root and the client accepts it. So the rows above are
     * two VALID conflicting blocks, not an invalid answer. */
    for (size_t i = 0; i < 3; i++) tc->mocks[i].at[TARGET] = &F->fork;
    {
        cmt_light_client_t       *c = NULL;
        cmt_light_client_error_t  err;
        uint8_t                   want[CMT_TMHASH_SIZE];
        int                       crc;

        T(root_auto(&tc->net, tc->net.n, g_buf, &t, hash,
                    &answers) == LIGHT_AUTO_OK && answers == 3 &&
          sh_hash(&F->fork, want) == 0 &&
          memcmp(hash, want, CMT_TMHASH_SIZE) == 0,
          "disagree: the fork alone is a root");
        crc = construct_auto(tc, t, hash, &c, &err);
        cmt_light_client_free(c);
        T(crc == CMT_OK && stored_is(tc, TARGET, &F->fork),
          "disagree: the fork verifies (validly signed)");
    }
    ret = 0;
out:
    if (tc != NULL) case_close(tc);
    free(tc);
    return ret;
}

/* ══ 3. SHORT, then the retry recovers ═══════════════════════════════ */

/* Proves: one answer is LIGHT_AUTO_SHORT and stores nothing; with a
 * second node answering the next attempt takes the root and the client is
 * built (a silent witness counts neither way). Fails if one answer were
 * taken as a root, or silence blocked the retry. */
static int t_short(void)
{
    tcase_t                  *tc = calloc(1, sizeof(*tc));
    cmt_light_client_t       *c = NULL;
    cmt_light_client_error_t  err;
    uint8_t                   hash[CMT_TMHASH_SIZE], want[CMT_TMHASH_SIZE];
    int64_t                   t = 0;
    size_t                    answers = 0;
    int                       ret = 1;

    T(tc != NULL && case_open(tc, 3) == 0, "short: case");
    tc->mocks[1].dead = true;
    tc->mocks[2].dead = true;
    T(root_auto(&tc->net, tc->net.n, g_buf, &t, hash,
                &answers) == LIGHT_AUTO_SHORT,
      "short: one answer is not a root");
    T(store_last(tc) == -1, "short: nothing stored");

    /* No node connected at all: SHORT too (cmd_run retries). */
    for (size_t i = 0; i < 3; i++) {
        tc->net.clients[i].state = NODUS_CLIENT_DISCONNECTED;
    }
    T(root_auto(&tc->net, tc->net.n, g_buf, &t, hash,
                &answers) == LIGHT_AUTO_SHORT,
      "short: no connected node is SHORT, not a stop");
    for (size_t i = 0; i < 3; i++) {
        tc->net.clients[i].state = NODUS_CLIENT_READY;
    }

    /* The next attempt: node 1 answers again. */
    tc->mocks[1].dead = false;
    T(root_auto(&tc->net, tc->net.n, g_buf, &t, hash,
                &answers) == LIGHT_AUTO_OK, "short: the retry takes the root");
    T(sh_hash(&F->chain[TARGET], want) == 0 && t == TARGET &&
      memcmp(hash, want, CMT_TMHASH_SIZE) == 0 && answers == 2,
      "short: the root is the target with two answers");
    T(construct_auto(tc, t, hash, &c, &err) == CMT_OK && c != NULL,
      "short: the client is constructed with a silent witness present");
    T(store_last(tc) == TARGET && stored_is(tc, TARGET, &F->chain[TARGET]),
      "short: the store holds the root");
    ret = 0;
out:
    cmt_light_client_free(c);
    if (tc != NULL) case_close(tc);
    free(tc);
    return ret;
}

/* ══ 4. EXPIRED: re-root over a stored block older than 48 h ═════════ */

/* One expired-store case: `stored` is saved at height 1, root_pick must
 * choose the automatic root, and after the construction the store's
 * latest block is the target; `kept` says whether height 1 survives (the
 * primary confirms it) or is removed by the re-root (confirm_reroot). */
static int expired_case(const char *name, const tsh_t *stored, bool kept)
{
    tcase_t                  *tc = calloc(1, sizeof(*tc));
    cmt_light_client_t       *c = NULL;
    cmt_light_client_error_t  err;
    uint8_t                   hash[CMT_TMHASH_SIZE];
    int64_t                   t = 0;
    size_t                    answers = 0;
    int                       mode;
    int                       ret = 1;

    T(tc != NULL && case_open(tc, 3) == 0, name);
    T(store_save_block(tc, stored) == CMT_OK && store_last(tc) == 1, name);
    /* Block 1 is at bTime + 1 min; 48 h after it, it has expired. */
    g_now = cmt_time_add_ns(t_at(MINUTE), NODUS_LIGHT_TRUSTING_PERIOD_NS);
    g_clock_calls = 0;
    T(pick(tc, &mode) == 0 && mode == LIGHT_ROOT_AUTO,
      "expired: a stored block past 48 h takes the automatic root");
    T(g_clock_calls == 1, "expired: the clock was read once");
    T(root_auto(&tc->net, tc->net.n, g_buf, &t, hash,
                &answers) == LIGHT_AUTO_OK && t == TARGET,
      "expired: root_auto OK at the target");
    T(construct_auto(tc, t, hash, &c, &err) == CMT_OK && c != NULL,
      "expired: the client is constructed over the new root");
    T(store_last(tc) == TARGET && stored_is(tc, TARGET, &F->chain[TARGET]),
      "expired: the store's latest block is the new root");
    if (kept) {
        T(stored_is(tc, 1, stored) && store_first(tc) == 1,
          "expired: a stored block the primary confirms is kept");
    } else {
        T(!stored_any(tc, 1) && store_first(tc) == TARGET,
          "expired: a stored block the primary does not confirm is removed");
    }
    ret = 0;
out:
    cmt_light_client_free(c);
    if (tc != NULL) case_close(tc);
    free(tc);
    return ret;
}

/* Proves: K25-2 decides root_pick — expiry == now is expired (automatic
 * root), 1 ns before it resumes from the store; an expired store is
 * re-rooted and its latest block becomes the new target. Fails if
 * root_pick resumed an expired block, re-rooted a fresh one, or the
 * construction kept the old root as the latest. */
static int t_expired(void)
{
    tcase_t *tc = calloc(1, sizeof(*tc));
    int      mode;
    int      ret = 1;

    /* The counterpart: inside the period → the store (step 3). */
    T(tc != NULL && case_open(tc, 3) == 0, "fresh: case");
    T(store_save_block(tc, &F->chain[1]) == CMT_OK, "fresh: save");
    g_now = cmt_time_add_ns(t_at(MINUTE), NODUS_LIGHT_TRUSTING_PERIOD_NS - 1);
    T(pick(tc, &mode) == 0 && mode == LIGHT_ROOT_STORE,
      "fresh: 1 ns before expiry resumes from the store");
    g_now = t_at(HOUR);
    T(pick(tc, &mode) == 0 && mode == LIGHT_ROOT_STORE,
      "fresh: one hour old resumes from the store");
    T(tc->mocks[0].calls == 0, "fresh: root_pick asks no node");
    case_close(tc);

    if (expired_case("expired: unconfirmed stored block", &F->alt1,
                     false) != 0) {
        goto out;
    }
    if (expired_case("expired: confirmed stored block", &F->chain[1],
                     true) != 0) {
        goto out;
    }
    ret = 0;
out:
    if (tc != NULL) case_close(tc);
    free(tc);
    return ret;
}

/* ══ 5. LOCKED ════════════════════════════════════════════════════════ */

/* Proves: K25-10 — an uncleared attack record keeps root_pick on the
 * store even when the stored block has expired (where it would otherwise
 * take the automatic root); the client built from the store comes up
 * locked, the automatic construction is refused, and the store is
 * unchanged. Fails if a locked store took a new root. */
static int t_locked(void)
{
    static const uint8_t      REC[] = { 'a', 't', 't', 'a', 'c', 'k' };
    tcase_t                  *tc = calloc(1, sizeof(*tc));
    cmt_light_client_t       *c = NULL;
    cmt_light_client_error_t  err;
    cmt_light_client_options_t opts;
    bool                      is_auto = false;
    uint8_t                   hash[CMT_TMHASH_SIZE];
    uint64_t                  seq = 0;
    int                       mode;
    int                       ret = 1;

    T(tc != NULL && case_open(tc, 3) == 0, "locked: case");
    T(store_save_block(tc, &F->chain[1]) == CMT_OK, "locked: save");
    g_now = cmt_time_add_ns(t_at(MINUTE), 3 * NODUS_LIGHT_TRUSTING_PERIOD_NS);
    T(pick(tc, &mode) == 0 && mode == LIGHT_ROOT_AUTO,
      "locked: without a record the expired store takes the automatic root");
    T(cmt_light_store_db_save_attack_record(tc->st.db, REC, sizeof(REC),
                                            &seq) == CMT_OK && seq == 1,
      "locked: attack record written");
    T(pick(tc, &mode) == 0 && mode == LIGHT_ROOT_STORE,
      "locked: an uncleared record keeps the store, no automatic root");

    /* cmd_run's LIGHT_ROOT_STORE branch. */
    run_opts(&opts, &is_auto);
    memset(&err, 0, sizeof(err));
    net_assign(&tc->net, 0);
    T(cmt_light_client_new_from_trusted_store(
            g_chain, sizeof(g_chain), NODUS_LIGHT_TRUSTING_PERIOD_NS,
            &tc->net.primary, tc->net.witnesses, tc->net.n_witnesses,
            &tc->st.store, &opts, &c, &err) == CMT_OK && c != NULL,
      "locked: the client is built from the store");
    T(cmt_light_client_attack_locked(c), "locked: the client comes up locked");
    cmt_light_client_free(c);
    c = NULL;

    /* Even if the automatic root were reached, the library refuses it. */
    T(sh_hash(&F->chain[TARGET], hash) == 0 &&
      construct_auto(tc, TARGET, hash, &c, &err) == CMT_REJECT &&
      err.code == CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED && c == NULL,
      "locked: a new root over a locked store is refused");
    T(store_last(tc) == 1 && store_first(tc) == 1 &&
      stored_is(tc, 1, &F->chain[1]), "locked: the store is unchanged");
    T(tc->mocks[0].calls == 0 && tc->mocks[1].calls == 0 &&
      tc->mocks[2].calls == 0, "locked: no node was asked for a block");
    ret = 0;
out:
    cmt_light_client_free(c);
    if (tc != NULL) case_close(tc);
    free(tc);
    return ret;
}

/* ══ 6. PINNED ONLY (K25-11) ══════════════════════════════════════════ */

/* Proves: a slot at or above `n_pinned` — where light_refresh appends the
 * nodes it adds — is asked by root_auto neither as the primary nor at the
 * target. Fails if root_auto looped to net->n: slot 3 would give a
 * second answer (OK) or a conflicting one (DISAGREE), and its counter
 * would move. */
static int t_pinned_only(void)
{
    tcase_t *tc = calloc(1, sizeof(*tc));
    uint8_t  hash[CMT_TMHASH_SIZE];
    int64_t  t = 0;
    size_t   answers = 0;
    int      ret = 1;

    T(tc != NULL && case_open(tc, 4) == 0, "pinned: case");
    /* Pinned slots 0..2: only slot 0 answers. Slot 3 is a refresh slot. */
    tc->mocks[1].dead = true;
    tc->mocks[2].dead = true;
    T(root_auto(&tc->net, 3, g_buf, &t, hash, &answers) == LIGHT_AUTO_SHORT,
      "pinned: a refresh slot holding the same block is not counted");
    T(tc->mocks[3].calls == 0, "pinned: the refresh slot was not asked");

    tc->mocks[3].at[TARGET] = &F->fork;
    T(root_auto(&tc->net, 3, g_buf, &t, hash, &answers) == LIGHT_AUTO_SHORT,
      "pinned: a refresh slot holding a fork does not stop the start");
    T(tc->mocks[3].calls == 0, "pinned: still not asked");

    /* No pinned slot connected; the refresh slot is: no primary from it. */
    for (size_t i = 0; i < 3; i++) {
        tc->net.clients[i].state = NODUS_CLIENT_DISCONNECTED;
    }
    tc->mocks[3].at[TARGET] = &F->chain[TARGET];
    T(root_auto(&tc->net, 3, g_buf, &t, hash, &answers) == LIGHT_AUTO_SHORT,
      "pinned: a refresh slot is never the primary");
    T(tc->mocks[3].calls == 0, "pinned: never asked");
    ret = 0;
out:
    if (tc != NULL) case_close(tc);
    free(tc);
    return ret;
}

/* ══ 7. auto_construct_retryable ══════════════════════════════════════ */

/* Proves: the construction refusals cmd_run retries are exactly
 * INIT_AGREEMENT_SHORT and PROVIDER with NO_RESPONSE / HEIGHT_TOO_HIGH. */
static int t_retryable(void)
{
    cmt_light_client_error_t e;
    int                      ret = 1;

    memset(&e, 0, sizeof(e));
    e.code = CMT_LIGHT_CLIENT_ERR_INIT_AGREEMENT_SHORT;
    T(auto_construct_retryable(CMT_REJECT, &e), "retry: agreement short");
    T(!auto_construct_retryable(CMT_FAULT, &e), "retry: a fault is not");
    e.code          = CMT_LIGHT_CLIENT_ERR_PROVIDER;
    e.provider.code = CMT_LIGHT_PROVIDER_ERR_NO_RESPONSE;
    T(auto_construct_retryable(CMT_REJECT, &e), "retry: no response");
    e.provider.code = CMT_LIGHT_PROVIDER_ERR_HEIGHT_TOO_HIGH;
    T(auto_construct_retryable(CMT_REJECT, &e), "retry: height too high");
    e.provider.code = CMT_LIGHT_PROVIDER_ERR_LIGHT_BLOCK_NOT_FOUND;
    T(!auto_construct_retryable(CMT_REJECT, &e), "retry: not found is not");
    e.provider.code = CMT_LIGHT_PROVIDER_ERR_BAD_LIGHT_BLOCK;
    T(!auto_construct_retryable(CMT_REJECT, &e), "retry: bad block is not");
    e.code          = CMT_LIGHT_CLIENT_ERR_HASH_MISMATCH;
    e.provider.code = CMT_LIGHT_PROVIDER_ERR_NONE;
    T(!auto_construct_retryable(CMT_REJECT, &e), "retry: hash mismatch is not");
    e.code = CMT_LIGHT_CLIENT_ERR_ATTACK_LOCKED;
    T(!auto_construct_retryable(CMT_REJECT, &e), "retry: locked is not");
    ret = 0;
out:
    return ret;
}

/* ══ 8. light_compat_judge — the update-required log line ═════════════ */

/* Proves (design docs/plans/2026-10-20-update-required-warning-design.md
 * §1 B, nodus-light "a log line at start and on each refresh"): the line
 * is logged once per distinct (outcome, generation, next generation, next
 * height) — never again for the same state, even when the tip (and so
 * the "in N blocks" text) moves; a new switch height, a new outcome or a
 * state that comes back after an OK answer is logged again; an OK answer
 * is never logged. The RPC half (light_compat_check) is not driven: it
 * needs a live session (HOW IT CAN LIE 2). */
static int t_compat_judge(void)
{
    light_compat_state_t      st;
    nodus_dnac_ruleset_info_t ri;
    char                      msg[NODUS_LIGHT_COMPAT_MSG_MAX];
    int                       ret = 1;

    memset(&st, 0, sizeof(st));
    memset(&ri, 0, sizeof(ri));
    ri.tip        = 900;
    ri.generation = 5;
    T(!light_compat_judge(&st, &ri, 5, msg, sizeof(msg)), "compat: OK not logged");
    T(msg[0] == '\0', "compat: OK has no message");

    ri.next_generation = 5;   /* a switch this build carries */
    ri.next_height     = 1000;
    T(!light_compat_judge(&st, &ri, 5, msg, sizeof(msg)),
      "compat: a carried switch is not logged");

    ri.next_generation = 6;   /* a switch this build does not carry */
    T(light_compat_judge(&st, &ri, 5, msg, sizeof(msg)),
      "compat: update-before logged");
    T(strstr(msg, "generation 6") != NULL && strstr(msg, "block 1000") != NULL,
      "compat: update-before names generation and block");
    T(strstr(msg, "Update soon") != NULL &&
      strstr(msg, "in 100 blocks") != NULL &&
      strstr(msg, "this nodus-light knows up to 5") != NULL,
      "compat: update-before is nodus-light's own line");
    T(strstr(msg, "stop") == NULL && strstr(msg, "transaction") == NULL,
      "compat: the line claims nothing about what stops working");
    ri.tip = 950;
    T(!light_compat_judge(&st, &ri, 5, msg, sizeof(msg)),
      "compat: same state, later tip, not logged again");
    ri.next_height = 1100;
    T(light_compat_judge(&st, &ri, 5, msg, sizeof(msg)),
      "compat: a new switch height is logged");
    T(!light_compat_judge(&st, &ri, 5, msg, sizeof(msg)),
      "compat: and only once");

    ri.generation = 6;        /* the switch happened */
    ri.tip        = 1200;
    T(light_compat_judge(&st, &ri, 5, msg, sizeof(msg)),
      "compat: update-required logged");
    T(strstr(msg, "Update required") != NULL &&
      strstr(msg, "generation 6") != NULL,
      "compat: update-required names the generation");
    T(strstr(msg, "this nodus-light knows up to 5") != NULL,
      "compat: update-required names what nodus-light knows");
    T(NODUS_LIGHT_GEN_MAX == NODUS_RT_GEN_ROOTS,
      "compat: nodus-light judges by the roots generation");
    T(!light_compat_judge(&st, &ri, 5, msg, sizeof(msg)),
      "compat: update-required only once");

    T(!light_compat_judge(&st, &ri, 6, msg, sizeof(msg)),
      "compat: a build that carries it is OK");
    T(light_compat_judge(&st, &ri, 5, msg, sizeof(msg)),
      "compat: the state after an OK answer is logged again");

    T(!light_compat_judge(NULL, &ri, 5, msg, sizeof(msg)), "compat: NULL state");
    T(!light_compat_judge(&st, NULL, 5, msg, sizeof(msg)), "compat: NULL answer");
    ret = 0;
out:
    return ret;
}

/* ══ 9. parse_args — network file / --pin / --chain precedence ════════ */

/* Proves (DHT v2 3c round 3): (1) a --network file with more nodes than
 * nodus-light holds (NODUS_LIGHT_MAX_NODES) is REFUSED, not cut; (2) the
 * precedence — explicit --chain-id over --chain over the file's chain id,
 * whatever the order of the options; the file's nodes over the built-in
 * list; --pin over the file's pins; explicit --node pins over --pin (and a
 * --node list replaces the file's nodes). REQUIRES: json-c (NODUS_HAS_JSONC,
 * the default build). The file is one mkstemp file under /tmp, removed. HOW
 * IT CAN LIE: it drives parse_args only — nothing here connects, so it says
 * nothing about what a session does with the chosen pins and chain id. */
#ifdef NODUS_HAS_JSONC
static int write_net_file(char *path, size_t n_nodes)
{
    static const char fp3[] =
        "3333333333333333333333333333333333333333333333333333333333333333"
        "3333333333333333333333333333333333333333333333333333333333333333";
    int   fd = mkstemp(path);
    FILE *f  = fd >= 0 ? fdopen(fd, "w") : NULL;

    if (f == NULL) return -1;
    fprintf(f, "{\"chain_id\":\"%s\",\"nodes\":[",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    for (size_t i = 0; i < n_nodes; i++)
        fprintf(f, "%s{\"ip\":\"10.0.0.%zu\",\"port\":4001,\"fp\":\"%s\"}",
                i ? "," : "", i + 1, fp3);
    fprintf(f, "]}");
    return fclose(f);
}

static int t_args_precedence(void)
{
    static const char C_FILE[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static const char C_FLAG[] =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    static const char C_EXPL[] =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    static const char P_GEN[] =
        "2222222222222222222222222222222222222222222222222222222222222222"
        "2222222222222222222222222222222222222222222222222222222222222222";
    static const char NODE_A[] =
        "h1:4001:1111111111111111111111111111111111111111111111111111111111111111"
        "1111111111111111111111111111111111111111111111111111111111111111";
    static const char NODE_B[] =
        "h2:4001:1111111111111111111111111111111111111111111111111111111111111111"
        "1111111111111111111111111111111111111111111111111111111111111111";
    char          big[] = "/tmp/test_nodus_light_big_XXXXXX";
    char          two[] = "/tmp/test_nodus_light_two_XXXXXX";
    light_args_t *a = (light_args_t *)malloc(sizeof(*a));
    int           ret = 1;

    T(a != NULL, "args: allocation");
    T(write_net_file(big, NODUS_LIGHT_MAX_NODES + 1) == 0, "args: write big file");
    T(write_net_file(two, 2) == 0, "args: write two-node file");

    {   /* 1: too many nodes -> refused, not cut */
        char *v[] = { "x", "run", "--data", "d", "--network", big };
        T(parse_args(6, v, 2, true, true, true, a) == -1,
          "args: a file with more nodes than nodus-light holds is refused");
    }
    {   /* file alone: its chain id and its 2 nodes */
        char *v[] = { "x", "run", "--data", "d", "--network", two };
        T(parse_args(6, v, 2, true, true, true, a) == 0 && a->n_nodes == 2 &&
          strcmp(a->chain_id_hex, C_FILE) == 0 &&
          strcmp(a->nodes[0].host, "10.0.0.1") == 0 &&
          a->nodes[0].pin.bytes[0] == 0x33,
          "args: the file's nodes and chain id replace the built-in ones");
    }
    {   /* --chain over the file */
        char *v[] = { "x", "run", "--data", "d", "--network", two,
                      "--chain", (char *)C_FLAG };
        T(parse_args(8, v, 2, true, true, true, a) == 0 &&
          strcmp(a->chain_id_hex, C_FLAG) == 0, "args: --chain over the file");
    }
    {   /* --chain-id over --chain, in both option orders */
        char *v1[] = { "x", "run", "--data", "d", "--network", two,
                       "--chain-id", (char *)C_EXPL, "--chain", (char *)C_FLAG };
        char *v2[] = { "x", "run", "--data", "d", "--network", two,
                       "--chain", (char *)C_FLAG, "--chain-id", (char *)C_EXPL };
        T(parse_args(10, v1, 2, true, true, true, a) == 0 &&
          strcmp(a->chain_id_hex, C_EXPL) == 0,
          "args: --chain-id wins over a later --chain");
        T(parse_args(10, v2, 2, true, true, true, a) == 0 &&
          strcmp(a->chain_id_hex, C_EXPL) == 0,
          "args: --chain-id wins over an earlier --chain");
    }
    {   /* --pin over the file's pins */
        char *v[] = { "x", "run", "--data", "d", "--network", two,
                      "--pin", (char *)P_GEN };
        T(parse_args(8, v, 2, true, true, true, a) == 0 && a->n_nodes == 2 &&
          a->nodes[0].pin.bytes[0] == 0x22 && a->nodes[1].pin.bytes[0] == 0x22,
          "args: --pin over the file's pins");
    }
    {   /* explicit --node pins over --pin; the --node list replaces the file's */
        char *v[] = { "x", "run", "--data", "d", "--network", two,
                      "--pin", (char *)P_GEN, "--node", (char *)NODE_A,
                      "--node", (char *)NODE_B };
        T(parse_args(12, v, 2, true, true, true, a) == 0 && a->n_nodes == 2 &&
          strcmp(a->nodes[0].host, "h1") == 0 &&
          a->nodes[0].pin.bytes[0] == 0x11 && a->nodes[1].pin.bytes[0] == 0x11,
          "args: explicit --node pins are never overwritten by --pin");
    }
    ret = 0;
out:
    unlink(big);
    unlink(two);
    free(a);
    return ret;
}
#endif /* NODUS_HAS_JSONC */

/* The program's functions this test does not call, referenced so the
 * included source builds without unused-function warnings. */
static void keep_program_functions(void)
{
    (void)cmd_run;
    (void)cmd_status;
    (void)cmd_clear_attack;
}

int main(void)
{
    int rc = 1;

    keep_program_functions();
    pat(g_chain, sizeof(g_chain), 0xC1);
    g_scratch = (cmt_valset_scratch_t *)malloc(sizeof(*g_scratch));
    g_buf     = cmt_light_block_buf_new();
    g_out     = cmt_light_block_buf_new();
    F         = (tfix_t *)calloc(1, sizeof(*F));
    if (g_scratch == NULL || g_buf == NULL || g_out == NULL || F == NULL) {
        fprintf(stderr, "allocation failed\n");
        goto out;
    }
    if (build_keys() != 0 || build_fixture() != 0) {
        fprintf(stderr, "fixture failed\n");
        goto out;
    }
    if (t_agree() != 0) goto out;
    if (t_disagree() != 0) goto out;
    if (t_short() != 0) goto out;
    if (t_expired() != 0) goto out;
    if (t_locked() != 0) goto out;
    if (t_pinned_only() != 0) goto out;
    if (t_retryable() != 0) goto out;
    if (t_compat_judge() != 0) goto out;
#ifdef NODUS_HAS_JSONC
    if (t_args_precedence() != 0) goto out;
#endif

    printf("test_nodus_light: %d checks OK\n", g_checks);
    rc = 0;
out:
    free(F);
    cmt_light_block_buf_free(g_buf);
    cmt_light_block_buf_free(g_out);
    free(g_scratch);
    return rc;
}
