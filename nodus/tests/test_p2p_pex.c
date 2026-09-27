/**
 * @file nodus/tests/test_p2p_pex.c
 * @brief Tests for shared/dnac/cmt_p2p_{netaddr (proto conversions),
 *        addrbook, pex} — cometbft @709fd12b p2p/netaddress.go:139-186,
 *        p2p/pex/addrbook.go, known_address.go, params.go, file.go and
 *        pex_reactor.go ported to C, with the signed ADDR records of
 *        R-P2P-4 (fleet P2P-PORT, F4).
 *
 * Governing: docs/plans/2026-09-26-p2p-port-design.md §2 (pex row), §4,
 * §5 (R-P2P-4, -24, -31), §6, §7 (G7);
 * docs/plans/decisions/2026-09-26-witness-port-session.md "N7 SON",
 * "N7 ADDR bayt düzeni"; docs/plans/2026-09-26-witness-port-session-
 * design.md §2R3 N7 FINAL, §2R4 P4, P5.
 *
 * WHAT IT PROVES (each would be false if its case failed):
 *   · NetAddress proto: ToProto + Marshal is byte-exact to types.pb.go's
 *     field order (id, ip, port; zero fields omitted); Unmarshal skips an
 *     unknown field and refuses a wrong wire type; FromProto refuses a bad
 *     IP and a port ≥ 1<<16, and an over-long ID becomes an ID that
 *     Valid() refuses.
 *   · PEX codec: PexRequest is `0a 00`; PexAddrs with one address is the
 *     generated encoding, and the NOT GROUNDED `more` field is `18 01`
 *     after the addresses.
 *   · address book: add → pick → MarkGood moves it to an OLD bucket
 *     (IsGood); MarkBad bans and removes; ReinstateBadPeers does nothing
 *     before the ban ends and afterwards re-adds a NEW entry but DROPS an
 *     entry that was old when banned (the reference's own addToNewBucket
 *     refusal, addrbook.go:531-533); AddAddress's refusals (invalid,
 *     private, private source, ours, non-routable under strict).
 *   · bucket placement: two books fed the same random bytes compute the
 *     same key and the same new/old bucket for the same address, the entry
 *     sits in the bucket calcNewBucket names, another key moves it; the
 *     group keys (/16, "local" under strict, IPv6 /32, he.net /36).
 *   · GetSelection / GetSelectionWithBias return max(min(32, n), 23 % of
 *     n) capped at 250 addresses for books of 10, 150 and 1 200.
 *   · signed ADDR (R-P2P-4): a valid record is accepted and its seq kept;
 *     an EQUAL and a LOWER seq are refused; a higher seq at a new ip moves
 *     the entry; another chain id, a chain key that is not the record's
 *     pk_fp, a signature by another key, a 0x0A (not 0x0B) signature, an
 *     entry whose port differs, a record of an unbonded ID are each
 *     refused with their own code; an unsigned address of an unbonded ID
 *     is accepted as a hint; an unsigned address of a BONDED ID is refused
 *     — also through the switch's AddrBook seam; our own record is
 *     refused as ErrAddrBookSelf after its seq is remembered.
 *   · save / load: the entries (old / new, the record and its seq) come
 *     back, the record re-verified; a record whose signature byte was
 *     flipped in the file is dropped at load; an entry whose ID is no
 *     longer bonded keeps its address as a hint without the record; a
 *     file that does not decode makes start fail.
 *   · PEX over two switches (REAL ML-DSA-87 / ML-KEM-1024 keys, in-memory
 *     pipes): the dialer asks, the answer lands in its book and the
 *     request is closed; a later unrequested PexAddrs stops the sender and
 *     bans it; a third request inside the interval stops and bans the
 *     requester; a private peer's address is in neither book; a
 *     validator's own record is pushed after connect (no ban, no stop),
 *     re-pushed after a change only once ensurePeersPeriod has passed, and
 *     a foreign record pushed by another peer stops that peer;
 *     ensurePeers dials exactly max_num_outbound_peers addresses from the
 *     book; a 21-record answer (> 64 000 bytes) arrives whole in parts.
 *
 * WHAT IT REQUIRES: nothing beyond a default nodus build (no compile
 * flags, no environment). WHAT IT LEAVES BEHIND: nothing (no files, no
 * sockets, no threads).
 *
 * HOW IT CAN LIE: time is a FAKE clock, the randomness a seeded xorshift
 * and the network in-memory pipes driven in a fixed order — the cases
 * prove the rules and thresholds, not behaviour under real sockets or
 * load. The byte vectors are hand-derived from types.pb.go / pex.pb.go's
 * MarshalToSizedBuffer, not taken from a live cometbft peer. The split
 * case proves every part fitted the receiver's RecvMessageCapacity (the
 * MConnection would have stopped the peer otherwise) and that the whole
 * answer arrived; it does not count the parts on the wire. The record
 * verification runs synchronously here (R-P2P-43).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_netaddr.h"
#include "dnac/cmt_p2p_nodeinfo.h"
#include "dnac/cmt_p2p_peer.h"
#include "dnac/cmt_p2p_transport.h"
#include "dnac/cmt_p2p_switch.h"
#include "dnac/cmt_p2p_addrbook.h"
#include "dnac/cmt_p2p_pex.h"
#include "dnac/cmt_block.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "crypto/hash/qgp_sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define TEST(name) do { printf("  %-70s", name); fflush(stdout); } while (0)
#define PASS()     do { printf("PASS\n"); passed++; } while (0)
#define FAIL(msg)  do { printf("FAIL: %s\n", msg); failed++; } while (0)
#define CHECK(c)   do { if (!(c)) { ok = 0; printf("\n    check failed: %s (line %d)", #c, __LINE__); } } while (0)

static int passed = 0;
static int failed = 0;

#define MS  (1000LL * 1000)
#define SEC (1000LL * MS)
#define HOUR (3600LL * SEC)

static int64_t g_now = 1000 * MS;                        /* monotonic */
static const int64_t WALL_BASE = 1790000000LL * SEC;     /* wall = base + g_now */
static uint64_t g_prng = 0x9e3779b97f4a7c15ULL;

static const uint8_t CHAIN_A[32] = { 0x9a, 0xbf, 0x84, 0x37, 0xe7, 0x29 };
static const uint8_t CHAIN_B[32] = { 0x11, 0x22, 0x33 };

static uint64_t xorshift(void)
{
    g_prng ^= g_prng << 13;
    g_prng ^= g_prng >> 7;
    g_prng ^= g_prng << 17;
    return g_prng;
}

static int64_t prng_int63n(void *ctx, int64_t n)
{
    (void)ctx;
    return n <= 0 ? 0 : (int64_t)((xorshift() >> 1) % (uint64_t)n);
}

static int prng_bytes(void *ctx, uint8_t *out, size_t n)
{
    size_t i;

    (void)ctx;
    for (i = 0; i < n; i++) {
        out[i] = (uint8_t)xorshift();
    }
    return 0;
}

static int64_t wall_now(void *ctx)
{
    (void)ctx;
    return WALL_BASE + g_now;
}

static int64_t mono_now(void *ctx)
{
    (void)ctx;
    return g_now;
}

/* ══ validators: identities, bonded sets, records ═══════════════════ */

typedef struct {
    nodus_identity_t id;
    char idhex[CMT_P2P_ID_CAP];
} val_t;

static int val_make(val_t *v)
{
    if (nodus_identity_generate(&v->id) != 0) {
        return -1;
    }
    return cmt_p2p_pubkey_to_id(v->id.pk.bytes, v->idhex) == CMT_OK ? 0 : -1;
}

/* payload ‖ signature, signed under `purpose` 0x0B (or 0x0A for the
 * wrong-purpose case) by `signer`, naming `named`'s key. */
static int make_rec(const nodus_identity_t *signer, const nodus_identity_t *named,
                    const uint8_t chain[32], const char *ip, uint16_t port,
                    uint64_t seq, bool wrong_purpose, uint8_t rec[CMT_P2P_ADDR_REC_SIZE])
{
    uint8_t fp[64];
    cmt_p2p_ip_t a;
    nodus_sig_t sig;
    int rc;

    if (qgp_sha3_512(named->pk.bytes, sizeof(named->pk.bytes), fp) != 0 ||
        !cmt_p2p_ip_parse(ip, strlen(ip), &a) ||
        cmt_p2p_addr_rec_payload(chain, fp, &a, port, seq, rec) != CMT_OK) {
        return -1;
    }
    rc = wrong_purpose
        ? nodus_sign_session_auth(&sig, rec, CMT_P2P_ADDR_REC_PAYLOAD_SIZE, &signer->sk)
        : nodus_sign_witness_addr(&sig, rec, CMT_P2P_ADDR_REC_PAYLOAD_SIZE, &signer->sk);
    if (rc != 0) {
        return -1;
    }
    memcpy(rec + CMT_P2P_ADDR_REC_PAYLOAD_SIZE, sig.bytes, CMT_P2P_ADDR_REC_SIG_SIZE);
    return 0;
}

/* A bonded set as the book's host sees it. */
#define MAX_BONDED 32
typedef struct {
    const nodus_identity_t *ids[MAX_BONDED];
    int n;
    /* `swap_key`: answer this ID with another key (the RECORD_KEY case) */
    const char *swap_id;
    const nodus_identity_t *swap_to;
    /* the saved file */
    uint8_t *file;
    size_t file_len;
    int n_saves;
} bset_t;

static bool bs_pubkey(void *ctx, const char *id, uint8_t pk[QGP_DSA87_PUBLICKEYBYTES])
{
    bset_t *b = (bset_t *)ctx;
    int i;

    for (i = 0; i < b->n; i++) {
        char h[CMT_P2P_ID_CAP];

        if (cmt_p2p_pubkey_to_id(b->ids[i]->pk.bytes, h) == CMT_OK && strcmp(h, id) == 0) {
            if (b->swap_id != NULL && strcmp(b->swap_id, id) == 0) {
                memcpy(pk, b->swap_to->pk.bytes, QGP_DSA87_PUBLICKEYBYTES);
            } else {
                memcpy(pk, b->ids[i]->pk.bytes, QGP_DSA87_PUBLICKEYBYTES);
            }
            return true;
        }
    }
    return false;
}

static int bs_verify(void *ctx, const uint8_t *payload, size_t len,
                     const uint8_t sig_in[CMT_P2P_ADDR_REC_SIG_SIZE],
                     const uint8_t pk_in[QGP_DSA87_PUBLICKEYBYTES])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_ADDR_REC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, QGP_DSA87_PUBLICKEYBYTES);
    return nodus_verify_witness_addr(&sig, payload, len, &pk);
}

static int bs_save(void *ctx, const uint8_t *bytes, size_t len)
{
    bset_t *b = (bset_t *)ctx;

    free(b->file);
    b->file = (uint8_t *)malloc(len > 0 ? len : 1);
    if (b->file == NULL) {
        return -1;
    }
    memcpy(b->file, bytes, len);
    b->file_len = len;
    b->n_saves++;
    return 0;
}

static int bs_load(void *ctx, uint8_t **bytes, size_t *len)
{
    bset_t *b = (bset_t *)ctx;

    if (b->file == NULL) {
        return 1;
    }
    *bytes = (uint8_t *)malloc(b->file_len > 0 ? b->file_len : 1);
    if (*bytes == NULL) {
        return -1;
    }
    memcpy(*bytes, b->file, b->file_len);
    *len = b->file_len;
    return 0;
}

static cmt_p2p_addrbook_t *book_new(bset_t *b, bool strict, const uint8_t chain[32],
                                    const char *self_id)
{
    cmt_p2p_ab_config_t cfg;
    cmt_p2p_ab_host_t h;

    memset(&cfg, 0, sizeof(cfg));
    cfg.routability_strict = strict;
    memcpy(cfg.chain_id, chain, 32);
    if (self_id != NULL) {
        snprintf(cfg.self_id, sizeof(cfg.self_id), "%s", self_id);
    }
    memset(&h, 0, sizeof(h));
    h.ctx = b;
    h.now_ns = wall_now;
    h.rand_bytes = prng_bytes;
    h.rand_int63n = prng_int63n;
    h.bonded_pubkey = bs_pubkey;
    h.verify_addr = bs_verify;
    h.save = bs_save;
    h.load = bs_load;
    return cmt_p2p_addrbook_new(&cfg, &h);
}

static cmt_p2p_netaddr_t na(const char *id, const char *ip, uint16_t port)
{
    cmt_p2p_ip_t a;
    cmt_p2p_netaddr_t n;

    memset(&a, 0, sizeof(a));
    (void)cmt_p2p_ip_parse(ip, strlen(ip), &a);
    n = cmt_p2p_netaddr_new_ip_port(&a, port);
    if (id != NULL) {
        snprintf(n.id, sizeof(n.id), "%s", id);
    }
    return n;
}

/* A 64-hex ID from a number. */
static void num_id(unsigned k, char out[CMT_P2P_ID_CAP])
{
    snprintf(out, CMT_P2P_ID_CAP, "%056x%08x", 0xabcdu, k);
}

/* ══ the in-memory network (the F3 harness, test_p2p_switch.c) ══════ */

typedef struct {
    uint8_t *b;
    size_t   len;
    size_t   cap;
} pipe_t;

static void pipe_push(pipe_t *p, const uint8_t *b, size_t n)
{
    if (n == 0) {
        return;
    }
    if (p->len + n > p->cap) {
        size_t ncap = p->cap == 0 ? 65536 : p->cap;

        while (ncap < p->len + n) {
            ncap *= 2;
        }
        p->b = (uint8_t *)realloc(p->b, ncap);
        p->cap = ncap;
    }
    memcpy(p->b + p->len, b, n);
    p->len += n;
}

static void pipe_pop(pipe_t *p, size_t n)
{
    if (n >= p->len) {
        p->len = 0;
        return;
    }
    memmove(p->b, p->b + n, p->len - n);
    p->len -= n;
}

typedef struct node node_t;

#define MAX_NODES   10
#define MAX_WIRES   64
#define MAX_PENDING 32
#define JOBQ        16

typedef struct {
    bool     used;
    node_t  *a;
    int      a_slot;
    uint64_t a_gen;
    bool     a_open;
    bool     a_eof;
    node_t  *b;
    int      b_slot;
    uint64_t b_gen;
    bool     b_open;
    bool     b_eof;
    pipe_t   ab;
    pipe_t   ba;
} wire_t;

typedef struct {
    bool              used;
    node_t           *src;
    int               slot;
    uint64_t          gen;
    cmt_p2p_netaddr_t to;
} pending_t;

struct node {
    const char       *name;
    nodus_identity_t  id;
    char              idhex[CMT_P2P_ID_CAP];
    cmt_p2p_ip_t      ip;
    uint16_t          port;
    cmt_p2p_node_info_t *ni;
    cmt_p2p_transport_t  t;
    cmt_p2p_switch_t     sw;
    bool up;
    cmt_p2p_hs_job_t *jobs[2][JOBQ];
    int  njobs[2];
    int  n_dials;
    bset_t bonded;
    cmt_p2p_addrbook_t *book;
    cmt_p2p_addr_book_t seam;
    cmt_p2p_pex_t *pex;
    bool has_own;
    uint8_t own_rec[CMT_P2P_ADDR_REC_SIZE];
};

static node_t   *g_nodes[MAX_NODES];
static int       g_n_nodes;
static uint16_t  g_next_eph = 40000;
static wire_t    g_wires[MAX_WIRES];
static pending_t g_pending[MAX_PENDING];

static node_t *find_node(const cmt_p2p_ip_t *ip, uint16_t port)
{
    int i;

    for (i = 0; i < g_n_nodes; i++) {
        if (g_nodes[i] != NULL && g_nodes[i]->port == port &&
            cmt_p2p_ip_equal(&g_nodes[i]->ip, ip)) {
            return g_nodes[i];
        }
    }
    return NULL;
}

static int h_dial(void *ctx, int slot, uint64_t gen, const cmt_p2p_netaddr_t *addr,
                  uint64_t *handle)
{
    node_t *n = (node_t *)ctx;
    node_t *to = find_node(&addr->ip, addr->port);
    int i;

    n->n_dials++;
    *handle = 0;
    if (to == NULL || !to->up) {
        return -1;
    }
    for (i = 0; i < MAX_PENDING; i++) {
        if (!g_pending[i].used) {
            g_pending[i].used = true;
            g_pending[i].src = n;
            g_pending[i].slot = slot;
            g_pending[i].gen = gen;
            g_pending[i].to = *addr;
            return 0;
        }
    }
    return -1;
}

static void h_close(void *ctx, int slot, uint64_t gen, uint64_t handle)
{
    node_t *n = (node_t *)ctx;
    int i;

    (void)handle;
    for (i = 0; i < MAX_WIRES; i++) {
        wire_t *w = &g_wires[i];

        if (!w->used) {
            continue;
        }
        if (w->a == n && w->a_slot == slot && w->a_gen == gen) {
            w->a_open = false;
        }
        if (w->b == n && w->b_slot == slot && w->b_gen == gen) {
            w->b_open = false;
        }
    }
    for (i = 0; i < MAX_PENDING; i++) {
        if (g_pending[i].used && g_pending[i].src == n &&
            g_pending[i].slot == slot && g_pending[i].gen == gen) {
            g_pending[i].used = false;
        }
    }
}

static int h_submit(void *ctx, cmt_p2p_hs_job_t *job)
{
    node_t *n = (node_t *)ctx;
    int c = (int)job->job_class;

    if (n->njobs[c] >= JOBQ) {
        return -1;
    }
    n->jobs[c][n->njobs[c]++] = job;
    return 0;
}

static int h_bonded_count(void *ctx)
{
    return ((node_t *)ctx)->bonded.n;
}

static int64_t h_rand_zero(void *ctx, int64_t n)
{
    (void)ctx;
    (void)n;
    return 0;
}

static bool h_is_bonded(void *ctx, const char *id)
{
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];

    return bs_pubkey(&((node_t *)ctx)->bonded, id, pk);
}

static int sc_sign(void *ctx, const uint8_t *msg, size_t len,
                   uint8_t sig_out[CMT_P2P_SC_SIG_SIZE])
{
    node_t *n = (node_t *)ctx;
    nodus_sig_t sig;
    int rc = nodus_sign_session_auth(&sig, msg, len, &n->id.sk);

    memcpy(sig_out, sig.bytes, CMT_P2P_SC_SIG_SIZE);
    return rc;
}

static int sc_verify(void *ctx, const uint8_t sig_in[CMT_P2P_SC_SIG_SIZE],
                     const uint8_t *msg, size_t len,
                     const uint8_t pk_in[CMT_P2P_SC_DSA_PK_SIZE])
{
    nodus_sig_t sig;
    nodus_pubkey_t pk;

    (void)ctx;
    memcpy(sig.bytes, sig_in, CMT_P2P_SC_SIG_SIZE);
    memcpy(pk.bytes, pk_in, CMT_P2P_SC_DSA_PK_SIZE);
    return nodus_verify_session_auth(&sig, msg, len, &pk);
}

static bool h_own_record(void *ctx, uint8_t rec[CMT_P2P_ADDR_REC_SIZE])
{
    node_t *n = (node_t *)ctx;

    if (!n->has_own) {
        return false;
    }
    memcpy(rec, n->own_rec, CMT_P2P_ADDR_REC_SIZE);
    return true;
}

typedef struct {
    const char *ip;
    uint16_t    port;
    int         max_out;
    const nodus_identity_t *identity;
} node_params_t;

static node_t *node_new(const char *name, const node_params_t *prm)
{
    node_t *n = (node_t *)calloc(1, sizeof(node_t));
    cmt_p2p_transport_host_t th;
    cmt_p2p_transport_config_t tc;
    cmt_p2p_switch_host_t sh;
    cmt_p2p_switch_config_t sc;
    cmt_p2p_node_info_params_t nip;
    cmt_p2p_pex_config_t pc;
    cmt_p2p_pex_host_t ph;
    cmt_p2p_reactor_t r;
    cmt_p2p_netaddr_t laddr;
    char listen[64];
    static const uint8_t chans[] = { CMT_P2P_PEX_CHANNEL };

    if (n == NULL) {
        return NULL;
    }
    n->name = name;
    if (prm->identity != NULL) {
        n->id = *prm->identity;
    } else if (nodus_identity_generate(&n->id) != 0 || !n->id.has_mlkem) {
        free(n);
        return NULL;
    }
    if (cmt_p2p_pubkey_to_id(n->id.pk.bytes, n->idhex) != CMT_OK ||
        !cmt_p2p_ip_parse(prm->ip, strlen(prm->ip), &n->ip)) {
        free(n);
        return NULL;
    }
    n->port = prm->port;
    n->up = true;

    n->ni = (cmt_p2p_node_info_t *)calloc(1, sizeof(*n->ni));
    snprintf(listen, sizeof(listen), "%s:%u", prm->ip, (unsigned)prm->port);
    memset(&nip, 0, sizeof(nip));
    nip.block_version = CMT_BLOCK_PROTOCOL;
    nip.node_id = n->idhex;
    nip.chain_id = CHAIN_A;
    nip.version = "0.19.80";
    nip.channels = chans;
    nip.n_channels = 1;
    nip.moniker = name;
    nip.tx_index = "off";
    nip.rpc_address = "";
    nip.listen_addr = listen;
    if (n->ni == NULL || cmt_p2p_node_info_make(n->ni, &nip) != CMT_P2P_ERR_NONE) {
        free(n->ni);
        free(n);
        return NULL;
    }
    memset(&th, 0, sizeof(th));
    th.ctx = n;
    th.now_ns = mono_now;
    th.dial = h_dial;
    th.close = h_close;
    th.submit_job = h_submit;
    th.bonded_count = h_bonded_count;
    memset(&tc, 0, sizeof(tc));
    tc.dsa_pk = n->id.pk.bytes;
    tc.kem_pk = n->id.mlkem_pk;
    tc.kem_sk = n->id.mlkem_sk;
    tc.sc_host.ctx = n;
    tc.sc_host.sign = sc_sign;
    tc.sc_host.verify = sc_verify;
    tc.chain_id = CHAIN_A;
    tc.node_info = n->ni;
    cmt_p2p_mconn_p2p_default_config(&tc.mconn);
    tc.max_num_inbound_peers = 40;
    if (cmt_p2p_transport_init(&n->t, &th, &tc) != CMT_OK) {
        free(n->ni);
        free(n);
        return NULL;
    }
    laddr = cmt_p2p_netaddr_new_ip_port(&n->ip, n->port);
    memcpy(laddr.id, n->idhex, sizeof(laddr.id));
    cmt_p2p_transport_listen(&n->t, &laddr);

    memset(&sh, 0, sizeof(sh));
    sh.ctx = n;
    sh.rand_int63n = h_rand_zero;
    sh.is_bonded = h_is_bonded;
    cmt_p2p_switch_default_config(&sc);
    if (prm->max_out > 0) {
        sc.max_num_outbound_peers = prm->max_out;
    }
    if (cmt_p2p_switch_init(&n->sw, &sc, &n->t, &sh) != CMT_OK) {
        cmt_p2p_transport_free(&n->t);
        free(n->ni);
        free(n);
        return NULL;
    }
    /* node/setup.go:446-470 — the book, our address, SetAddrBook */
    n->book = book_new(&n->bonded, false, CHAIN_A, n->idhex);
    if (n->book == NULL) {
        cmt_p2p_switch_free(&n->sw);
        cmt_p2p_transport_free(&n->t);
        free(n->ni);
        free(n);
        return NULL;
    }
    cmt_p2p_addrbook_add_our_address(n->book, &laddr);
    cmt_p2p_addrbook_switch_seam(n->book, &n->seam);
    cmt_p2p_switch_set_addr_book(&n->sw, &n->seam);
    /* node/setup.go:473-491 — the PEX reactor */
    memset(&pc, 0, sizeof(pc));
    memset(&ph, 0, sizeof(ph));
    ph.ctx = n;
    ph.now_ns = mono_now;
    ph.rand_int63n = prng_int63n;
    ph.own_record = h_own_record;
    n->pex = cmt_p2p_pex_new(&pc, &ph, n->book, &n->sw);
    if (n->pex == NULL) {
        cmt_p2p_addrbook_free(n->book);
        cmt_p2p_switch_free(&n->sw);
        cmt_p2p_transport_free(&n->t);
        free(n->ni);
        free(n);
        return NULL;
    }
    cmt_p2p_pex_reactor(n->pex, &r);
    if (cmt_p2p_switch_add_reactor(&n->sw, &r) != CMT_OK) {
        cmt_p2p_pex_free(n->pex);
        cmt_p2p_addrbook_free(n->book);
        cmt_p2p_switch_free(&n->sw);
        cmt_p2p_transport_free(&n->t);
        free(n->ni);
        free(n);
        return NULL;
    }
    g_nodes[g_n_nodes++] = n;
    return n;
}

static bool node_start(node_t *n)
{
    return cmt_p2p_switch_start(&n->sw) == CMT_OK;
}

static void run(int rounds, int64_t step_ns);

/* One pass right after start: every started node, having no peer and no
 * dial, runs its first ensurePeers at once (pex_reactor.go:415-421) and
 * the next one a full ensurePeersPeriod later — so no jitter-timed
 * request lands inside a case's short window. */
static void settle(void)
{
    run(1, 10 * MS);
}

static void drop_jobs(node_t *n)
{
    int c, i;

    for (c = 0; c < 2; c++) {
        for (i = 0; i < n->njobs[c]; i++) {
            n->jobs[c][i]->rc = -1;
            (void)cmt_p2p_transport_job_done(&n->t, n->jobs[c][i]);
        }
        n->njobs[c] = 0;
    }
}

static void world_reset(void)
{
    int i;

    for (i = 0; i < g_n_nodes; i++) {
        node_t *n = g_nodes[i];

        drop_jobs(n);
        cmt_p2p_switch_free(&n->sw);
        cmt_p2p_pex_free(n->pex);
        cmt_p2p_addrbook_free(n->book);
        cmt_p2p_transport_free(&n->t);
        free(n->bonded.file);
        free(n->ni);
        free(n);
        g_nodes[i] = NULL;
    }
    g_n_nodes = 0;
    for (i = 0; i < MAX_WIRES; i++) {
        free(g_wires[i].ab.b);
        free(g_wires[i].ba.b);
    }
    memset(g_wires, 0, sizeof(g_wires));
    memset(g_pending, 0, sizeof(g_pending));
}

static void run_jobs(node_t *n)
{
    int c;

    for (c = 1; c >= 0; c--) {
        while (n->njobs[c] > 0) {
            cmt_p2p_hs_job_t *j = n->jobs[c][0];

            memmove(&n->jobs[c][0], &n->jobs[c][1],
                    (size_t)(n->njobs[c] - 1) * sizeof(cmt_p2p_hs_job_t *));
            n->njobs[c]--;
            (void)cmt_p2p_hs_job_run(j);
            (void)cmt_p2p_transport_job_done(&n->t, j);
        }
    }
}

static void move_bytes(node_t *from, int fs, uint64_t fg, bool from_open,
                       pipe_t *p, node_t *to, int ts, uint64_t tg, bool to_open)
{
    if (from_open) {
        size_t len = 0;
        const uint8_t *o = cmt_p2p_transport_write_buf(&from->t, fs, fg, &len);

        if (o != NULL && len > 0) {
            pipe_push(p, o, len);
            cmt_p2p_transport_write_done(&from->t, fs, fg, len);
        }
    }
    if (to_open && p->len > 0) {
        size_t room = 0;
        uint8_t *in = cmt_p2p_transport_read_buf(&to->t, ts, tg, &room);

        if (in != NULL && room > 0) {
            size_t k = p->len < room ? p->len : room;

            memcpy(in, p->b, k);
            pipe_pop(p, k);
            cmt_p2p_transport_read_done(&to->t, ts, tg, k);
        }
    }
}

static void net_step(void)
{
    int i;

    for (i = 0; i < MAX_PENDING; i++) {
        pending_t *pd = &g_pending[i];
        node_t *to;
        int slot = -1, w, rc;
        uint64_t gen = 0;

        if (!pd->used) {
            continue;
        }
        to = find_node(&pd->to.ip, pd->to.port);
        if (to == NULL || !to->up) {
            pd->used = false;
            cmt_p2p_transport_conn_failed(&pd->src->t, pd->slot, pd->gen);
            continue;
        }
        if (!cmt_p2p_transport_can_accept(&to->t)) {
            continue;
        }
        rc = cmt_p2p_transport_accept(&to->t, &pd->src->ip, g_next_eph++, 0, &slot, &gen);
        pd->used = false;
        if (rc != CMT_P2P_ERR_NONE) {
            cmt_p2p_transport_conn_failed(&pd->src->t, pd->slot, pd->gen);
            continue;
        }
        for (w = 0; w < MAX_WIRES; w++) {
            if (!g_wires[w].used) {
                break;
            }
        }
        if (w == MAX_WIRES) {
            continue;
        }
        g_wires[w].used = true;
        g_wires[w].a = pd->src;
        g_wires[w].a_slot = pd->slot;
        g_wires[w].a_gen = pd->gen;
        g_wires[w].a_open = true;
        g_wires[w].a_eof = false;
        g_wires[w].b = to;
        g_wires[w].b_slot = slot;
        g_wires[w].b_gen = gen;
        g_wires[w].b_open = true;
        g_wires[w].b_eof = false;
        g_wires[w].ab.len = 0;
        g_wires[w].ba.len = 0;
        cmt_p2p_transport_dial_connected(&pd->src->t, pd->slot, pd->gen,
                                         &to->ip, to->port);
    }
    for (i = 0; i < g_n_nodes; i++) {
        run_jobs(g_nodes[i]);
    }
    for (i = 0; i < MAX_WIRES; i++) {
        wire_t *w = &g_wires[i];

        if (!w->used) {
            continue;
        }
        move_bytes(w->a, w->a_slot, w->a_gen, w->a_open, &w->ab,
                   w->b, w->b_slot, w->b_gen, w->b_open);
        move_bytes(w->b, w->b_slot, w->b_gen, w->b_open, &w->ba,
                   w->a, w->a_slot, w->a_gen, w->a_open);
        if (!w->a_open && w->b_open && !w->b_eof && w->ab.len == 0) {
            w->b_eof = true;
            cmt_p2p_transport_conn_failed(&w->b->t, w->b_slot, w->b_gen);
        }
        if (!w->b_open && w->a_open && !w->a_eof && w->ba.len == 0) {
            w->a_eof = true;
            cmt_p2p_transport_conn_failed(&w->a->t, w->a_slot, w->a_gen);
        }
        if (!w->a_open && !w->b_open) {
            w->used = false;
        }
    }
    for (i = 0; i < g_n_nodes; i++) {
        cmt_p2p_switch_tick(&g_nodes[i]->sw);
        cmt_p2p_pex_tick(g_nodes[i]->pex);
    }
}

static void run(int rounds, int64_t step_ns)
{
    int i;

    for (i = 0; i < rounds; i++) {
        g_now += step_ns;
        net_step();
    }
}

static cmt_p2p_netaddr_t addr_of(const node_t *n)
{
    cmt_p2p_netaddr_t a = cmt_p2p_netaddr_new_ip_port(&n->ip, n->port);

    memcpy(a.id, n->idhex, sizeof(a.id));
    return a;
}

static cmt_p2p_peer_t *peer_of(node_t *n, const node_t *other)
{
    return cmt_p2p_peer_set_get(cmt_p2p_switch_peers(&n->sw), other->idhex);
}

static bool dial(node_t *from, const node_t *to)
{
    cmt_p2p_netaddr_t a = addr_of(to);

    return cmt_p2p_switch_dial_peer_with_address(&from->sw, &a) == CMT_P2P_ERR_NONE;
}

static bool send_raw(node_t *from, const node_t *to, const uint8_t *b, size_t n)
{
    cmt_p2p_peer_t *p = peer_of(from, to);

    return p != NULL && cmt_p2p_peer_send(p, CMT_P2P_PEX_CHANNEL, b, n);
}

/* ══ 1. NetAddress proto (netaddress.go:139-186) ═════════════════════ */

static void test_netaddr_proto(void)
{
    static const uint8_t want[] = {
        0x0a, 0x02, 'a', 'b',
        0x12, 0x07, '1', '.', '2', '.', '3', '.', '4',
        0x18, 0xa0, 0xd0, 0x01
    };
    cmt_p2p_netaddr_t a = na("ab", "1.2.3.4", 26656), b;
    cmt_p2p_netaddr_pb_t pb, pb2;
    char ipb[CMT_P2P_IP_STR_MAX];
    uint8_t out[CMT_P2P_NETADDR_PROTO_MAX], in[160];
    size_t n = 0;
    int ok = 1;

    TEST("netaddress proto: ToProto/FromProto, bytes, refusals");
    CHECK(cmt_p2p_netaddr_to_proto(&a, ipb, &pb) == CMT_OK);
    CHECK(cmt_p2p_netaddr_pb_marshal(&pb, out, sizeof(out), &n) == CMT_OK);
    CHECK(n == sizeof(want) && memcmp(out, want, n) == 0);
    CHECK(cmt_p2p_netaddr_pb_unmarshal(out, n, &pb2) == CMT_OK);
    CHECK(cmt_p2p_netaddr_from_proto(&pb2, &b) == CMT_P2P_ERR_NONE);
    CHECK(cmt_p2p_netaddr_equals(&a, &b));
    /* an unknown field (7, varint) is skipped */
    memcpy(in, want, sizeof(want));
    in[sizeof(want)] = 0x38;
    in[sizeof(want) + 1] = 0x05;
    CHECK(cmt_p2p_netaddr_pb_unmarshal(in, sizeof(want) + 2, &pb2) == CMT_OK &&
          pb2.port == 26656);
    /* the IP field with a varint wire type is refused */
    in[0] = 0x10;
    in[1] = 0x01;
    CHECK(cmt_p2p_netaddr_pb_unmarshal(in, 2, &pb2) == CMT_REJECT);
    /* FromProto: a port ≥ 1<<16, a bad IP */
    pb2 = pb;
    pb2.port = 70000;
    CHECK(cmt_p2p_netaddr_from_proto(&pb2, &b) == CMT_P2P_ERR_NETADDR_INVALID);
    pb2 = pb;
    pb2.ip = (const uint8_t *)"1.2.3";
    pb2.ip_len = 5;
    CHECK(cmt_p2p_netaddr_from_proto(&pb2, &b) == CMT_P2P_ERR_NETADDR_INVALID);
    /* an over-long ID → an address Valid() refuses */
    {
        char longid[80];

        memset(longid, 'a', 65);
        longid[65] = '\0';
        pb2 = pb;
        pb2.id = (const uint8_t *)longid;
        pb2.id_len = 65;
        CHECK(cmt_p2p_netaddr_from_proto(&pb2, &b) == CMT_P2P_ERR_NONE);
        CHECK(cmt_p2p_netaddr_valid(&b) == CMT_P2P_ERR_NETADDR_INVALID);
    }
    /* NetAddressesToProto skips nil */
    {
        const cmt_p2p_netaddr_t *list[3] = { &a, NULL, &a };
        char bufs[3][CMT_P2P_IP_STR_MAX];
        cmt_p2p_netaddr_pb_t pbs[3];

        CHECK(cmt_p2p_netaddrs_to_proto(list, 3, bufs, pbs) == 2);
    }
    if (ok) {
        PASS();
    } else {
        FAIL("netaddr proto");
    }
}

/* ══ 2. PEX codec ════════════════════════════════════════════════════ */

static void test_pex_codec(void)
{
    uint8_t out[256];
    size_t n = 0;
    cmt_p2p_netaddr_t a = na("ab", "1.2.3.4", 26656);
    const cmt_p2p_netaddr_t *list[1] = { &a };
    static const uint8_t want_addrs[] = {
        0x12, 0x13, 0x0a, 0x11,
        0x0a, 0x02, 'a', 'b',
        0x12, 0x07, '1', '.', '2', '.', '3', '.', '4',
        0x18, 0xa0, 0xd0, 0x01
    };
    int ok = 1;

    TEST("pex codec: PexRequest `0a 00`, PexAddrs bytes, `more` = 18 01");
    CHECK(cmt_p2p_pex_marshal_request(out, sizeof(out), &n) == CMT_OK &&
          n == 2 && out[0] == 0x0a && out[1] == 0x00);
    CHECK(cmt_p2p_pex_marshal_addrs(list, 1, NULL, 0, false, out, sizeof(out), &n) == CMT_OK);
    CHECK(n == sizeof(want_addrs) && memcmp(out, want_addrs, n) == 0);
    CHECK(cmt_p2p_pex_marshal_addrs(list, 1, NULL, 0, true, out, sizeof(out), &n) == CMT_OK);
    CHECK(n == sizeof(want_addrs) + 2 && out[1] == 0x15 &&
          out[n - 2] == 0x18 && out[n - 1] == 0x01);
    CHECK(cmt_p2p_pex_marshal_addrs(NULL, 0, NULL, 0, false, out, sizeof(out), &n) == CMT_OK &&
          n == 2 && out[0] == 0x12 && out[1] == 0x00);
    CHECK(CMT_P2P_PEX_MAX_MSG_SIZE == 64000);
    if (ok) {
        PASS();
    } else {
        FAIL("pex codec");
    }
}

/* ══ 3. address book: add / pick / good / bad / reinstate ════════════ */

static void test_book_basic(void)
{
    bset_t bs;
    cmt_p2p_addrbook_t *a;
    char id1[CMT_P2P_ID_CAP], id2[CMT_P2P_ID_CAP], id3[CMT_P2P_ID_CAP];
    cmt_p2p_netaddr_t x, y, src = na(NULL, "8.8.0.1", 26656), got;
    int n_new = 0, n_old = 0, ok = 1;

    TEST("addrbook: add, pick, MarkGood → old, MarkBad → ban, reinstate");
    memset(&bs, 0, sizeof(bs));
    num_id(1, id1);
    num_id(2, id2);
    num_id(3, id3);
    snprintf(src.id, sizeof(src.id), "%s", id3);
    x = na(id1, "1.2.3.4", 26656);
    y = na(id2, "5.6.7.8", 26656);
    a = book_new(&bs, true, CHAIN_A, NULL);
    CHECK(a != NULL);
    if (a == NULL) {
        FAIL("setup");
        return;
    }
    CHECK(cmt_p2p_addrbook_empty(a));
    CHECK(!cmt_p2p_addrbook_pick_address(a, 50, &got));
    CHECK(cmt_p2p_addrbook_add_address(a, &x, &src) == CMT_P2P_AB_OK);
    CHECK(cmt_p2p_addrbook_size(a) == 1 && cmt_p2p_addrbook_has_address(a, &x));
    CHECK(cmt_p2p_addrbook_pick_address(a, 100, &got) && cmt_p2p_netaddr_equals(&got, &x));
    cmt_p2p_addrbook_mark_attempt(a, &x);
    {
        int32_t att = 0;

        CHECK(cmt_p2p_addrbook_entry(a, id1, NULL, NULL, NULL, &att) && att == 1);
    }
    cmt_p2p_addrbook_mark_good(a, id1);
    cmt_p2p_addrbook_counts(a, &n_new, &n_old);
    CHECK(cmt_p2p_addrbook_is_good(a, &x) && n_new == 0 && n_old == 1);
    CHECK(cmt_p2p_addrbook_pick_address(a, 0, &got) && cmt_p2p_netaddr_equals(&got, &x));
    /* an old address of a known ID ignores a new address (anti-eclipse) */
    {
        cmt_p2p_netaddr_t moved = na(id1, "9.9.9.9", 26656);

        CHECK(cmt_p2p_addrbook_add_address(a, &moved, &src) == CMT_P2P_AB_OK);
        CHECK(cmt_p2p_addrbook_pick_address(a, 0, &got) && cmt_p2p_netaddr_equals(&got, &x));
    }
    /* MarkBad on the OLD entry: banned and gone; after the ban the
     * reference's addToNewBucket refuses an old entry → dropped */
    cmt_p2p_addrbook_mark_bad(a, &x, 24 * HOUR);
    CHECK(cmt_p2p_addrbook_is_banned(a, &x) && !cmt_p2p_addrbook_has_address(a, &x));
    CHECK(cmt_p2p_addrbook_add_address(a, &x, &src) == CMT_P2P_AB_ERR_BANNED);
    cmt_p2p_addrbook_reinstate_bad_peers(a);
    CHECK(cmt_p2p_addrbook_is_banned(a, &x));
    g_now += 25 * HOUR;
    cmt_p2p_addrbook_reinstate_bad_peers(a);
    CHECK(!cmt_p2p_addrbook_is_banned(a, &x) && !cmt_p2p_addrbook_has_address(a, &x));
    /* MarkBad on a NEW entry comes back after the ban */
    CHECK(cmt_p2p_addrbook_add_address(a, &y, &src) == CMT_P2P_AB_OK);
    cmt_p2p_addrbook_mark_bad(a, &y, 1 * HOUR);
    CHECK(!cmt_p2p_addrbook_has_address(a, &y));
    g_now += 2 * HOUR;
    cmt_p2p_addrbook_reinstate_bad_peers(a);
    CHECK(cmt_p2p_addrbook_has_address(a, &y) && !cmt_p2p_addrbook_is_banned(a, &y));
    /* refusals (addrbook.go:645-672) */
    {
        cmt_p2p_netaddr_t noid = na(NULL, "1.2.3.5", 26656);
        cmt_p2p_netaddr_t priv = na(id3, "1.2.3.6", 26656);
        cmt_p2p_netaddr_t mine = na(id2, "4.4.4.4", 1);
        cmt_p2p_netaddr_t local = na(id1, "10.0.0.1", 26656);
        char pid[CMT_P2P_ID_CAP];
        const char *ids[1];

        num_id(9, pid);
        ids[0] = pid;
        CHECK(cmt_p2p_addrbook_add_address(a, &noid, &src) == CMT_P2P_AB_ERR_INVALID_ADDR);
        CHECK(cmt_p2p_addrbook_add_address(a, NULL, &src) == CMT_P2P_AB_ERR_NIL_ADDR);
        cmt_p2p_addrbook_add_private_ids(a, ids, 1);
        snprintf(priv.id, sizeof(priv.id), "%s", pid);
        CHECK(cmt_p2p_addrbook_add_address(a, &priv, &src) == CMT_P2P_AB_ERR_PRIVATE);
        {
            cmt_p2p_netaddr_t psrc = na(pid, "8.8.0.2", 1);
            cmt_p2p_netaddr_t z = na(id3, "1.2.3.7", 26656);

            CHECK(cmt_p2p_addrbook_add_address(a, &z, &psrc) == CMT_P2P_AB_ERR_PRIVATE_SRC);
        }
        cmt_p2p_addrbook_add_our_address(a, &mine);
        CHECK(cmt_p2p_addrbook_our_address(a, &mine));
        CHECK(cmt_p2p_addrbook_add_address(a, &mine, &src) == CMT_P2P_AB_ERR_SELF);
        CHECK(cmt_p2p_addrbook_add_address(a, &local, &src) == CMT_P2P_AB_ERR_NON_ROUTABLE);
    }
    cmt_p2p_addrbook_free(a);
    free(bs.file);
    if (ok) {
        PASS();
    } else {
        FAIL("addrbook basic");
    }
}

/* ══ 4. bucket placement ═════════════════════════════════════════════ */

static void test_book_buckets(void)
{
    bset_t b1, b2, b3;
    cmt_p2p_addrbook_t *a1, *a2, *a3;
    char id1[CMT_P2P_ID_CAP], g[64];
    cmt_p2p_netaddr_t x, src;
    uint64_t saved;
    int nb1, nb2, bk[4], nbk = 0, ok = 1, differ = 0, k;
    uint8_t type = 0;

    TEST("addrbook: bucket placement with a fixed key; group keys");
    memset(&b1, 0, sizeof(b1));
    memset(&b2, 0, sizeof(b2));
    memset(&b3, 0, sizeof(b3));
    num_id(1, id1);
    x = na(id1, "1.2.3.4", 26656);
    src = na(id1, "8.8.1.1", 26656);
    saved = g_prng;
    a1 = book_new(&b1, false, CHAIN_A, NULL);
    g_prng = saved;                        /* the same random stream */
    a2 = book_new(&b2, false, CHAIN_A, NULL);
    a3 = book_new(&b3, false, CHAIN_A, NULL);       /* another stream */
    CHECK(a1 != NULL && a2 != NULL && a3 != NULL);
    if (a1 == NULL || a2 == NULL || a3 == NULL) {
        FAIL("setup");
        return;
    }
    CHECK(strlen(cmt_p2p_addrbook_key(a1)) == CMT_P2P_AB_KEY_LEN);
    CHECK(strcmp(cmt_p2p_addrbook_key(a1), cmt_p2p_addrbook_key(a2)) == 0);
    CHECK(strcmp(cmt_p2p_addrbook_key(a1), cmt_p2p_addrbook_key(a3)) != 0);
    nb1 = cmt_p2p_addrbook_calc_new_bucket(a1, &x, &src);
    nb2 = cmt_p2p_addrbook_calc_new_bucket(a2, &x, &src);
    CHECK(nb1 >= 0 && nb1 < CMT_P2P_AB_NEW_BUCKET_COUNT && nb1 == nb2);
    CHECK(cmt_p2p_addrbook_calc_new_bucket(a1, &x, &src) == nb1);
    CHECK(cmt_p2p_addrbook_calc_old_bucket(a1, &x) == cmt_p2p_addrbook_calc_old_bucket(a2, &x));
    CHECK(cmt_p2p_addrbook_add_address(a1, &x, &src) == CMT_P2P_AB_OK);
    CHECK(cmt_p2p_addrbook_entry(a1, id1, &type, bk, &nbk, NULL) &&
          type == CMT_P2P_AB_BUCKET_TYPE_NEW && nbk == 1 && bk[0] == nb1);
    cmt_p2p_addrbook_mark_good(a1, id1);
    CHECK(cmt_p2p_addrbook_entry(a1, id1, &type, bk, &nbk, NULL) &&
          type == CMT_P2P_AB_BUCKET_TYPE_OLD && nbk == 1 &&
          bk[0] == cmt_p2p_addrbook_calc_old_bucket(a1, &x));
    /* another key places some of 16 sources elsewhere */
    for (k = 0; k < 16; k++) {
        char ip[32];
        cmt_p2p_netaddr_t s;

        snprintf(ip, sizeof(ip), "8.%d.1.1", 10 + k);
        s = na(id1, ip, 1);
        if (cmt_p2p_addrbook_calc_new_bucket(a1, &x, &s) !=
            cmt_p2p_addrbook_calc_new_bucket(a3, &x, &s)) {
            differ++;
        }
    }
    CHECK(differ > 0);
    /* groupKeyFor (addrbook.go:893-941) */
    CHECK(cmt_p2p_addrbook_group_key(&x, false, g, sizeof(g)) > 0 && strcmp(g, "1.2.0.0") == 0);
    {
        cmt_p2p_netaddr_t l = na(id1, "127.0.0.1", 1);
        cmt_p2p_netaddr_t p10 = na(id1, "10.1.2.3", 1);
        cmt_p2p_netaddr_t v6 = na(id1, "2001:db9:1:2::1", 1);
        cmt_p2p_netaddr_t he = na(id1, "2001:470:abcd:1::1", 1);

        CHECK(cmt_p2p_addrbook_group_key(&l, true, g, sizeof(g)) > 0 && strcmp(g, "local") == 0);
        CHECK(cmt_p2p_addrbook_group_key(&l, false, g, sizeof(g)) > 0 && strcmp(g, "127.0.0.0") == 0);
        CHECK(cmt_p2p_addrbook_group_key(&p10, true, g, sizeof(g)) > 0 &&
              strcmp(g, "unroutable") == 0);
        CHECK(cmt_p2p_addrbook_group_key(&v6, false, g, sizeof(g)) > 0 &&
              strcmp(g, "2001:db9::") == 0);
        CHECK(cmt_p2p_addrbook_group_key(&he, false, g, sizeof(g)) > 0 &&
              strcmp(g, "2001:470:a000::") == 0);
    }
    cmt_p2p_addrbook_free(a1);
    cmt_p2p_addrbook_free(a2);
    cmt_p2p_addrbook_free(a3);
    if (ok) {
        PASS();
    } else {
        FAIL("buckets");
    }
}

/* ══ 5. selection sizes ══════════════════════════════════════════════ */

static int expected_selection(int size)
{
    int n = size < 32 ? size : 32;
    int pct = size * 23 / 100;

    if (pct > n) {
        n = pct;
    }
    return n > 250 ? 250 : n;
}

static void test_book_selection(void)
{
    static const int sizes[] = { 10, 150, 1200 };
    cmt_p2p_netaddr_t *out = (cmt_p2p_netaddr_t *)calloc(CMT_P2P_AB_MAX_GET_SELECTION,
                                                         sizeof(*out));
    int s, ok = 1;

    TEST("addrbook: GetSelection / WithBias sizes (10, 150, 1200 entries)");
    if (out == NULL) {
        FAIL("memory");
        return;
    }
    for (s = 0; s < 3; s++) {
        bset_t bs;
        cmt_p2p_addrbook_t *a;
        int k, size, got, i, j, dup = 0;

        memset(&bs, 0, sizeof(bs));
        a = book_new(&bs, false, CHAIN_A, NULL);
        if (a == NULL) {
            ok = 0;
            break;
        }
        for (k = 0; k < sizes[s]; k++) {
            char id[CMT_P2P_ID_CAP], ip[32], sip[32];
            cmt_p2p_netaddr_t x, src;

            num_id(1000u + (unsigned)k, id);
            snprintf(ip, sizeof(ip), "%d.%d.%d.%d", 1 + k / 60000, (k / 250) % 240 + 1,
                     k % 250 + 1, 9);
            snprintf(sip, sizeof(sip), "7.%d.0.1", k % 97);
            x = na(id, ip, 26656);
            src = na(id, sip, 1);
            (void)cmt_p2p_addrbook_add_address(a, &x, &src);
        }
        size = cmt_p2p_addrbook_size(a);
        CHECK(size > 0 && size <= sizes[s]);
        got = cmt_p2p_addrbook_get_selection(a, out);
        CHECK(got == expected_selection(size));
        for (i = 0; i < got; i++) {
            for (j = i + 1; j < got; j++) {
                if (cmt_p2p_netaddr_equals(&out[i], &out[j])) {
                    dup = 1;
                }
            }
        }
        CHECK(!dup);
        got = cmt_p2p_addrbook_get_selection_with_bias(a, 30, out);
        CHECK(got == expected_selection(size));
        cmt_p2p_addrbook_free(a);
    }
    free(out);
    if (ok) {
        PASS();
    } else {
        FAIL("selection");
    }
}

/* ══ 6. signed ADDR records (R-P2P-4) ════════════════════════════════ */

static val_t *g_val;          /* V, W, U: made once (keygen is slow-ish) */

static void test_signed_addr(void)
{
    val_t *V = &g_val[0], *W = &g_val[1];
    bset_t bs;
    cmt_p2p_addrbook_t *a;
    uint8_t rec[CMT_P2P_ADDR_REC_SIZE];
    cmt_p2p_netaddr_t src = na(NULL, "8.8.0.1", 26656), out, e;
    uint64_t seq = 0;
    char uid[CMT_P2P_ID_CAP];
    int ok = 1;

    TEST("signed ADDR: accept, seq rules, chain / key / sig / 0x0B / ip-port");
    memset(&bs, 0, sizeof(bs));
    bs.ids[bs.n++] = &V->id;
    bs.ids[bs.n++] = &W->id;
    num_id(77, uid);
    snprintf(src.id, sizeof(src.id), "%s", uid);
    a = book_new(&bs, true, CHAIN_A, NULL);
    CHECK(a != NULL);
    if (a == NULL) {
        FAIL("setup");
        return;
    }
    /* valid */
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 5, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), &out) == CMT_P2P_AB_OK);
    CHECK(strcmp(out.id, V->idhex) == 0 && out.port == 4004);
    CHECK(cmt_p2p_addrbook_has_address(a, &out));
    CHECK(cmt_p2p_addrbook_record(a, V->idhex, &seq) != NULL && seq == 5);
    /* equal and lower seq are NOT newer (§2R4 P5) */
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) ==
          CMT_P2P_AB_ERR_RECORD_NOT_NEWER);
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 4, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) ==
          CMT_P2P_AB_ERR_RECORD_NOT_NEWER);
    /* higher seq, same ip: refreshed; higher seq, new ip: moved */
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 6, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) == CMT_P2P_AB_OK);
    CHECK(cmt_p2p_addrbook_record(a, V->idhex, &seq) != NULL && seq == 6);
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "6.6.6.6", 4004, 7, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), &out) == CMT_P2P_AB_OK);
    CHECK(cmt_p2p_addrbook_size(a) == 1 &&
          cmt_p2p_addrbook_pick_address(a, 100, &e) && cmt_p2p_netaddr_equals(&e, &out));
    /* another chain */
    CHECK(make_rec(&V->id, &V->id, CHAIN_B, "5.6.7.8", 4004, 9, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) ==
          CMT_P2P_AB_ERR_RECORD_CHAIN);
    /* V signs a record naming W's key → the chain key (W's) rejects V's signature */
    CHECK(make_rec(&V->id, &W->id, CHAIN_A, "5.6.7.9", 4004, 9, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) ==
          CMT_P2P_AB_ERR_RECORD_SIG);
    /* the chain answers V's ID with another key → pk_fp ≠ SHA3-512(chain pk) */
    bs.swap_id = V->idhex;
    bs.swap_to = &W->id;
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 9, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) ==
          CMT_P2P_AB_ERR_RECORD_KEY);
    bs.swap_id = NULL;
    /* a 0x0A signature over the same payload */
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 9, true, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) ==
          CMT_P2P_AB_ERR_RECORD_SIG);
    /* the entry's port is not the record's */
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 9, false, rec) == 0);
    e = na(V->idhex, "5.6.7.8", 4005);
    CHECK(cmt_p2p_addrbook_add_signed(a, &e, &src, rec, sizeof(rec), NULL) ==
          CMT_P2P_AB_ERR_RECORD_MISMATCH);
    /* malformed size / tag */
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec) - 1, NULL) ==
          CMT_P2P_AB_ERR_RECORD_MALFORMED);
    /* unsigned: an unbonded ID is a hint, a bonded one is refused (also
     * through the switch's AddrBook seam) */
    {
        cmt_p2p_addr_book_t seam;
        cmt_p2p_netaddr_t hint = na(uid, "3.3.3.3", 26656);
        cmt_p2p_netaddr_t vw = na(W->idhex, "4.4.4.4", 4004);

        CHECK(cmt_p2p_addrbook_add_address(a, &hint, &src) == CMT_P2P_AB_OK);
        CHECK(cmt_p2p_addrbook_add_address(a, &vw, &src) == CMT_P2P_AB_ERR_UNSIGNED_BONDED);
        cmt_p2p_addrbook_switch_seam(a, &seam);
        CHECK(seam.add_address(seam.ctx, &vw, &src) == CMT_P2P_AB_ERR_UNSIGNED_BONDED);
        CHECK(!cmt_p2p_addrbook_has_address(a, &vw));
    }
    /* a record of an unbonded identity */
    bs.n = 1;                                              /* W unbonded */
    CHECK(make_rec(&W->id, &W->id, CHAIN_A, "5.6.7.10", 4004, 1, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) ==
          CMT_P2P_AB_ERR_NOT_BONDED);
    cmt_p2p_addrbook_free(a);
    /* our own record: remembered, refused as self */
    bs.n = 2;
    a = book_new(&bs, true, CHAIN_A, V->idhex);
    CHECK(a != NULL);
    if (a != NULL) {
        CHECK(!cmt_p2p_addrbook_own_seq_seen(a, &seq));
        CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 42, false, rec) == 0);
        CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) ==
              CMT_P2P_AB_ERR_SELF);
        CHECK(cmt_p2p_addrbook_own_seq_seen(a, &seq) && seq == 42);
        cmt_p2p_addrbook_free(a);
    }
    free(bs.file);
    if (ok) {
        PASS();
    } else {
        FAIL("signed addr");
    }
}

/* ══ 6b. the ban list at scale; bonded IDs are never banned ══════════ */

#define N_BANS 300

/*
 * red-team M5 — the ban list (addrbook.go:97 badPeers, a map) is a
 * SORTED array searched in O(log n): N_BANS bans inserted in a scattered
 * order are each found (is_banned, add_address → ERR_BANNED), an ID never
 * banned is not, no bound drops any of them (the reference map has
 * none), and after the ban time every one is reinstated.
 * red-team Z2-F11 — a BONDED ID is never banned: MarkBad on a bonded
 * validator's signed entry leaves it in the book, unbanned. An identity
 * that BECOMES bonded loses its stale unsigned entry and any ban from
 * its unbonded days (cmt_p2p_addrbook_purge_bonded_unsigned), after
 * which its signed record is accepted at once (RED before the fix:
 * ERR_BANNED for the whole ban).
 */
static void test_book_bans(void)
{
    val_t *V = &g_val[0], *W = &g_val[1], *X = &g_val[2];
    bset_t bs;
    cmt_p2p_addrbook_t *a;
    cmt_p2p_netaddr_t src = na(NULL, "8.8.0.1", 26656), vaddr;
    uint8_t rec[CMT_P2P_ADDR_REC_SIZE];
    char id[CMT_P2P_ID_CAP], sid[CMT_P2P_ID_CAP], ip[32];
    int ok = 1, k, n_banned = 0;

    TEST("addrbook: 300 bans found in O(log n); bonded never banned; purge");
    memset(&bs, 0, sizeof(bs));
    bs.ids[bs.n++] = &V->id;                         /* V bonded, W / X not */
    num_id(99, sid);
    snprintf(src.id, sizeof(src.id), "%s", sid);
    a = book_new(&bs, true, CHAIN_A, NULL);
    CHECK(a != NULL);
    if (a == NULL) {
        FAIL("setup");
        return;
    }
    /* scattered insertion order: k -> (k * 7) mod N_BANS (7 ∤ 300) */
    for (k = 0; k < N_BANS; k++) {
        int j = (k * 7) % N_BANS;
        cmt_p2p_netaddr_t x;

        num_id(5000u + (unsigned)j, id);
        snprintf(ip, sizeof(ip), "%d.%d.3.1", 11 + j / 250, j % 250);
        x = na(id, ip, 26656);
        CHECK(cmt_p2p_addrbook_add_address(a, &x, &src) == CMT_P2P_AB_OK);
        cmt_p2p_addrbook_mark_bad(a, &x, 24 * HOUR);
    }
    for (k = 0; k < N_BANS; k++) {
        cmt_p2p_netaddr_t x;

        num_id(5000u + (unsigned)k, id);
        snprintf(ip, sizeof(ip), "%d.%d.3.1", 11 + k / 250, k % 250);
        x = na(id, ip, 26656);
        if (cmt_p2p_addrbook_is_banned(a, &x) &&
            cmt_p2p_addrbook_add_address(a, &x, &src) == CMT_P2P_AB_ERR_BANNED) {
            n_banned++;
        }
    }
    CHECK(n_banned == N_BANS);
    {
        cmt_p2p_netaddr_t never;

        num_id(5000u + N_BANS, id);                  /* past the last one */
        never = na(id, "13.0.3.1", 26656);
        CHECK(!cmt_p2p_addrbook_is_banned(a, &never));
        num_id(4999u, id);                           /* before the first */
        never = na(id, "13.0.3.2", 26656);
        CHECK(!cmt_p2p_addrbook_is_banned(a, &never));
    }
    g_now += 25 * HOUR;
    cmt_p2p_addrbook_reinstate_bad_peers(a);
    n_banned = 0;
    for (k = 0; k < N_BANS; k++) {
        cmt_p2p_netaddr_t x;

        num_id(5000u + (unsigned)k, id);
        snprintf(ip, sizeof(ip), "%d.%d.3.1", 11 + k / 250, k % 250);
        x = na(id, ip, 26656);
        if (cmt_p2p_addrbook_is_banned(a, &x)) {
            n_banned++;
        }
    }
    CHECK(n_banned == 0);

    /* Z2-F11 (a): MarkBad on bonded V's signed entry bans nothing */
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 3, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), &vaddr) ==
          CMT_P2P_AB_OK);
    cmt_p2p_addrbook_mark_bad(a, &vaddr, 24 * HOUR);
    CHECK(!cmt_p2p_addrbook_is_banned(a, &vaddr) &&
          cmt_p2p_addrbook_has_address(a, &vaddr));

    /* Z2-F11 (b): W has a stale UNSIGNED entry, X a ban — then both bond */
    {
        cmt_p2p_netaddr_t wold = na(W->idhex, "7.7.7.7", 4004);
        cmt_p2p_netaddr_t xold = na(X->idhex, "7.7.7.8", 4004);
        cmt_p2p_netaddr_t wnew;

        CHECK(cmt_p2p_addrbook_add_address(a, &wold, &src) == CMT_P2P_AB_OK);
        CHECK(cmt_p2p_addrbook_add_address(a, &xold, &src) == CMT_P2P_AB_OK);
        cmt_p2p_addrbook_mark_bad(a, &xold, 24 * HOUR);
        CHECK(cmt_p2p_addrbook_is_banned(a, &xold));
        bs.ids[bs.n++] = &W->id;
        bs.ids[bs.n++] = &X->id;
        CHECK(cmt_p2p_addrbook_purge_bonded_unsigned(a) == 2);
        CHECK(!cmt_p2p_addrbook_has_address(a, &wold));
        CHECK(!cmt_p2p_addrbook_is_banned(a, &xold));
        CHECK(cmt_p2p_addrbook_has_address(a, &vaddr));   /* signed: kept */
        CHECK(make_rec(&X->id, &X->id, CHAIN_A, "7.7.7.8", 4004, 1, false, rec) == 0);
        CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), NULL) ==
              CMT_P2P_AB_OK);
        CHECK(make_rec(&W->id, &W->id, CHAIN_A, "7.7.7.9", 4004, 1, false, rec) == 0);
        CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), &wnew) ==
              CMT_P2P_AB_OK);
        CHECK(cmt_p2p_addrbook_purge_bonded_unsigned(a) == 0);
    }
    cmt_p2p_addrbook_free(a);
    free(bs.file);
    if (ok) {
        PASS();
    } else {
        FAIL("bans");
    }
}

/*
 * red-team M1 (the book half): a record naming OUR identity is compared
 * by bytes at the highest seq seen. Our own record echoed back (same
 * seq, same bytes) is NOT "different" — the host must not re-sign; a
 * different record at that same seq IS (another signer holds our key);
 * a higher seq replaces both and is compared afresh.
 */
static void test_own_record_echo(void)
{
    val_t *V = &g_val[0];
    bset_t bs;
    cmt_p2p_addrbook_t *a;
    cmt_p2p_netaddr_t src = na(NULL, "8.8.0.1", 26656);
    uint8_t mine[CMT_P2P_ADDR_REC_SIZE], other[CMT_P2P_ADDR_REC_SIZE];
    uint64_t seq = 0;
    char sid[CMT_P2P_ID_CAP];
    int ok = 1;

    TEST("addrbook: own record echoed = same bytes; other signer = differs");
    memset(&bs, 0, sizeof(bs));
    bs.ids[bs.n++] = &V->id;
    num_id(98, sid);
    snprintf(src.id, sizeof(src.id), "%s", sid);
    a = book_new(&bs, true, CHAIN_A, V->idhex);
    CHECK(a != NULL);
    if (a == NULL) {
        FAIL("setup");
        return;
    }
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 10, false, mine) == 0);
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "9.9.9.9", 4004, 10, false, other) == 0);
    CHECK(!cmt_p2p_addrbook_own_seq_differs(a, mine));        /* nothing seen */
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, mine, sizeof(mine), NULL) ==
          CMT_P2P_AB_ERR_SELF);
    CHECK(cmt_p2p_addrbook_own_seq_seen(a, &seq) && seq == 10);
    CHECK(!cmt_p2p_addrbook_own_seq_differs(a, mine));        /* our echo */
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, mine, sizeof(mine), NULL) ==
          CMT_P2P_AB_ERR_SELF);
    CHECK(!cmt_p2p_addrbook_own_seq_differs(a, mine));        /* echoed again */
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, other, sizeof(other), NULL) ==
          CMT_P2P_AB_ERR_SELF);
    CHECK(cmt_p2p_addrbook_own_seq_seen(a, &seq) && seq == 10);
    CHECK(cmt_p2p_addrbook_own_seq_differs(a, mine));         /* another signer */
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 11, false, mine) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, mine, sizeof(mine), NULL) ==
          CMT_P2P_AB_ERR_SELF);
    CHECK(cmt_p2p_addrbook_own_seq_seen(a, &seq) && seq == 11);
    CHECK(!cmt_p2p_addrbook_own_seq_differs(a, mine));        /* fresh seq */
    cmt_p2p_addrbook_free(a);
    free(bs.file);
    if (ok) {
        PASS();
    } else {
        FAIL("own record echo");
    }
}

/* ══ 7. save / load ═════════════════════════════════════════════════ */

static void test_book_save_load(void)
{
    val_t *V = &g_val[0];
    bset_t bs, bs2, bs3, bs4, bs5;
    cmt_p2p_addrbook_t *a, *b;
    uint8_t rec[CMT_P2P_ADDR_REC_SIZE];
    char u1[CMT_P2P_ID_CAP], u2[CMT_P2P_ID_CAP], sid[CMT_P2P_ID_CAP];
    cmt_p2p_netaddr_t x1, x2, src, vaddr;
    uint64_t seq = 0;
    int ok = 1;
    size_t i;

    TEST("addrbook: save / load, records re-verified, tamper dropped");
    memset(&bs, 0, sizeof(bs));
    memset(&bs2, 0, sizeof(bs2));
    memset(&bs3, 0, sizeof(bs3));
    memset(&bs4, 0, sizeof(bs4));
    memset(&bs5, 0, sizeof(bs5));
    bs.ids[bs.n++] = &V->id;
    num_id(11, u1);
    num_id(12, u2);
    num_id(13, sid);
    x1 = na(u1, "11.1.1.1", 26656);
    x2 = na(u2, "12.1.1.1", 26656);
    src = na(sid, "13.1.1.1", 26656);
    a = book_new(&bs, true, CHAIN_A, NULL);
    CHECK(a != NULL);
    if (a == NULL) {
        FAIL("setup");
        return;
    }
    CHECK(cmt_p2p_addrbook_start(a) == CMT_OK);            /* no file yet */
    CHECK(cmt_p2p_addrbook_add_address(a, &x1, &src) == CMT_P2P_AB_OK);
    CHECK(cmt_p2p_addrbook_add_address(a, &x2, &src) == CMT_P2P_AB_OK);
    cmt_p2p_addrbook_mark_good(a, u1);
    CHECK(make_rec(&V->id, &V->id, CHAIN_A, "5.6.7.8", 4004, 3, false, rec) == 0);
    CHECK(cmt_p2p_addrbook_add_signed(a, NULL, &src, rec, sizeof(rec), &vaddr) == CMT_P2P_AB_OK);
    cmt_p2p_addrbook_save(a);
    CHECK(bs.file != NULL && bs.file_len > CMT_P2P_ADDR_REC_SIZE);
    /* round trip */
    bs2 = bs;
    bs2.file = (uint8_t *)malloc(bs.file_len);
    if (bs2.file != NULL) {
        memcpy(bs2.file, bs.file, bs.file_len);
    }
    b = book_new(&bs2, true, CHAIN_A, NULL);
    CHECK(b != NULL && cmt_p2p_addrbook_start(b) == CMT_OK);
    if (b != NULL) {
        CHECK(strcmp(cmt_p2p_addrbook_key(a), cmt_p2p_addrbook_key(b)) == 0);
        CHECK(cmt_p2p_addrbook_size(b) == 3);
        CHECK(cmt_p2p_addrbook_is_good(b, &x1) && !cmt_p2p_addrbook_is_good(b, &x2));
        CHECK(cmt_p2p_addrbook_has_address(b, &vaddr));
        CHECK(cmt_p2p_addrbook_record(b, V->idhex, &seq) != NULL && seq == 3);
        cmt_p2p_addrbook_free(b);
    }
    /* a flipped signature byte: that entry is dropped, the rest load */
    bs3 = bs;
    bs3.file = (uint8_t *)malloc(bs.file_len);
    if (bs3.file != NULL) {
        memcpy(bs3.file, bs.file, bs.file_len);
        for (i = 0; i + CMT_P2P_ADDR_REC_TAG_LEN <= bs3.file_len; i++) {
            if (memcmp(bs3.file + i, CMT_P2P_ADDR_REC_TAG, CMT_P2P_ADDR_REC_TAG_LEN) == 0) {
                bs3.file[i + CMT_P2P_ADDR_REC_PAYLOAD_SIZE + 100] ^= 0x01;
                break;
            }
        }
        CHECK(i + CMT_P2P_ADDR_REC_TAG_LEN <= bs3.file_len);
    }
    b = book_new(&bs3, true, CHAIN_A, NULL);
    CHECK(b != NULL && cmt_p2p_addrbook_start(b) == CMT_OK);
    if (b != NULL) {
        CHECK(cmt_p2p_addrbook_size(b) == 2 && !cmt_p2p_addrbook_has_address(b, &vaddr));
        CHECK(cmt_p2p_addrbook_has_address(b, &x1) && cmt_p2p_addrbook_has_address(b, &x2));
        cmt_p2p_addrbook_free(b);
    }
    /* V no longer bonded: its address stays as an unsigned hint */
    bs4 = bs;
    bs4.n = 0;
    bs4.file = (uint8_t *)malloc(bs.file_len);
    if (bs4.file != NULL) {
        memcpy(bs4.file, bs.file, bs.file_len);
    }
    b = book_new(&bs4, true, CHAIN_A, NULL);
    CHECK(b != NULL && cmt_p2p_addrbook_start(b) == CMT_OK);
    if (b != NULL) {
        CHECK(cmt_p2p_addrbook_has_address(b, &vaddr) &&
              cmt_p2p_addrbook_record(b, V->idhex, NULL) == NULL);
        cmt_p2p_addrbook_free(b);
    }
    /* a file that does not decode */
    bs5.file = (uint8_t *)malloc(4);
    if (bs5.file != NULL) {
        memcpy(bs5.file, "\x0a\x7f\x01\x02", 4);
        bs5.file_len = 4;
    }
    b = book_new(&bs5, true, CHAIN_A, NULL);
    CHECK(b != NULL && cmt_p2p_addrbook_start(b) == CMT_REJECT);
    cmt_p2p_addrbook_free(b);
    cmt_p2p_addrbook_stop(a);
    CHECK(bs.n_saves == 2);                               /* the stop's save */
    cmt_p2p_addrbook_free(a);
    free(bs.file);
    free(bs2.file);
    free(bs3.file);
    free(bs4.file);
    free(bs5.file);
    if (ok) {
        PASS();
    } else {
        FAIL("save/load");
    }
}

/* ══ 8. PEX: request → addrs; 9. unsolicited → stop + ban ════════════ */

static void test_pex_round_trip_and_unsolicited(void)
{
    node_params_t pa = { "20.0.0.1", 4004, 0, NULL }, pb = { "20.0.0.2", 4004, 0, NULL };
    node_t *A, *B;
    char h1[CMT_P2P_ID_CAP], h2[CMT_P2P_ID_CAP], h3[CMT_P2P_ID_CAP];
    cmt_p2p_netaddr_t x1, x2, x3, aaddr, bogus;
    uint8_t msg[256];
    size_t n = 0;
    int ok = 1;

    TEST("pex: request → addrs lands in the book; unsolicited → stop + ban");
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    num_id(21, h1);
    num_id(22, h2);
    num_id(23, h3);
    x1 = na(h1, "31.0.0.1", 4004);
    x2 = na(h2, "32.0.0.1", 4004);
    x3 = na(h3, "33.0.0.1", 4004);
    aaddr = addr_of(A);
    CHECK(cmt_p2p_addrbook_add_address(A->book, &x1, &aaddr) == CMT_P2P_AB_OK);
    CHECK(cmt_p2p_addrbook_add_address(A->book, &x2, &aaddr) == CMT_P2P_AB_OK);
    CHECK(cmt_p2p_addrbook_add_address(A->book, &x3, &aaddr) == CMT_P2P_AB_OK);
    CHECK(node_start(A) && node_start(B));
    settle();                /* A's first ensurePeers dials x1..x3: refused */
    {
        char s[CMT_P2P_NETADDR_STR_MAX];
        const char *peers[1];

        (void)cmt_p2p_netaddr_string(&aaddr, s, sizeof(s));
        peers[0] = s;
        CHECK(cmt_p2p_switch_dial_peers_async(&B->sw, peers, 1) == CMT_P2P_ERR_NONE);
    }
    CHECK(cmt_p2p_addrbook_has_address(B->book, &aaddr));  /* DialPeersAsync :503-520 */
    run(100, 10 * MS);
    CHECK(peer_of(B, A) != NULL && peer_of(A, B) != NULL);
    CHECK(cmt_p2p_addrbook_has_address(B->book, &x1) &&
          cmt_p2p_addrbook_has_address(B->book, &x2) &&
          cmt_p2p_addrbook_has_address(B->book, &x3));
    CHECK(!cmt_p2p_pex_request_outstanding(B->pex, A->idhex));
    /* A's inbound AddPeer put B's self-reported address in A's book */
    {
        cmt_p2p_netaddr_t baddr = addr_of(B);

        CHECK(cmt_p2p_addrbook_has_address(A->book, &baddr));
    }
    /* now A sends a list nobody asked for */
    bogus = na(h1, "41.0.0.1", 4004);
    {
        const cmt_p2p_netaddr_t *l[1] = { &bogus };

        CHECK(cmt_p2p_pex_marshal_addrs(l, 1, NULL, 0, false, msg, sizeof(msg), &n) == CMT_OK);
    }
    CHECK(send_raw(A, B, msg, n));
    run(50, 10 * MS);
    CHECK(peer_of(B, A) == NULL);
    CHECK(cmt_p2p_addrbook_is_banned(B->book, &aaddr));
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("round trip / unsolicited");
    }
}

/* ══ 10. request flood ═══════════════════════════════════════════════ */

static void test_pex_request_flood(void)
{
    node_params_t pa = { "20.0.1.1", 4004, 0, NULL }, pb = { "20.0.1.2", 4004, 0, NULL };
    node_t *A, *B;
    uint8_t req[8];
    size_t n = 0;
    cmt_p2p_netaddr_t baddr;
    int ok = 1;

    TEST("pex: a request inside minReceiveRequestInterval → stop + ban");
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    CHECK(node_start(A) && node_start(B));
    settle();
    CHECK(dial(B, A));
    run(100, 10 * MS);                  /* B's automatic request: free (:306-311) */
    CHECK(peer_of(A, B) != NULL && peer_of(B, A) != NULL);
    CHECK(!cmt_p2p_pex_request_outstanding(B->pex, A->idhex));
    /* the second, through RequestAddrs so its answer is solicited: the
     * free pass (:314-319); the third, raw, in the same instant: too
     * soon (:321-331). A reads both in one pass, in order. */
    cmt_p2p_pex_request_addrs(B->pex, peer_of(B, A));
    CHECK(cmt_p2p_pex_request_outstanding(B->pex, A->idhex));
    CHECK(cmt_p2p_pex_marshal_request(req, sizeof(req), &n) == CMT_OK);
    CHECK(send_raw(B, A, req, n));
    run(20, 10 * MS);
    baddr = addr_of(B);
    CHECK(peer_of(A, B) == NULL);
    CHECK(cmt_p2p_addrbook_is_banned(A->book, &baddr));
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("request flood");
    }
}

/* ══ 11. private peers ═══════════════════════════════════════════════ */

static void test_pex_private(void)
{
    node_params_t pa = { "20.0.2.1", 4004, 0, NULL }, pb = { "20.0.2.2", 4004, 0, NULL },
                  pp = { "20.0.2.3", 4004, 0, NULL };
    node_t *A, *B, *P;
    cmt_p2p_netaddr_t paddr;
    const char *ids[1];
    int ok = 1;

    TEST("pex: a private peer ID is gossiped by nobody");
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    P = node_new("P", &pp);
    if (A == NULL || B == NULL || P == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    ids[0] = P->idhex;
    CHECK(cmt_p2p_switch_add_private_peer_ids(&A->sw, ids, 1) == CMT_P2P_ERR_NONE);
    CHECK(node_start(A) && node_start(B) && node_start(P));
    settle();
    CHECK(dial(P, A));
    run(60, 10 * MS);
    CHECK(peer_of(A, P) != NULL);
    CHECK(dial(B, A));
    run(100, 10 * MS);
    CHECK(peer_of(A, B) != NULL && !cmt_p2p_pex_request_outstanding(B->pex, A->idhex));
    paddr = addr_of(P);
    CHECK(!cmt_p2p_addrbook_has_address(A->book, &paddr));
    CHECK(!cmt_p2p_addrbook_has_address(B->book, &paddr));
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("private");
    }
}

/* ══ 12. own-record push ═════════════════════════════════════════════ */

static void test_pex_push(void)
{
    node_params_t pa = { "20.0.3.1", 4004, 0, NULL }, pb = { "20.0.3.2", 4004, 0, NULL },
                  pc = { "20.0.3.3", 4004, 0, NULL };
    node_t *A, *B, *C;
    uint64_t seq = 0;
    cmt_p2p_netaddr_t aaddr;
    uint8_t buf[CMT_P2P_ADDR_REC_SIZE + 16];
    size_t n = 0;
    int ok = 1;

    TEST("pex: own record pushed after connect / change; foreign push stops");
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    C = node_new("C", &pc);
    if (A == NULL || B == NULL || C == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    /* A is a validator; B and A both know it as bonded */
    B->bonded.ids[B->bonded.n++] = &A->id;
    A->bonded.ids[A->bonded.n++] = &A->id;
    CHECK(make_rec(&A->id, &A->id, CHAIN_A, "20.0.3.1", 4004, 1, false, A->own_rec) == 0);
    A->has_own = true;
    CHECK(node_start(A) && node_start(B) && node_start(C));
    settle();
    CHECK(dial(A, B));
    run(100, 10 * MS);
    aaddr = addr_of(A);
    CHECK(peer_of(B, A) != NULL);
    CHECK(cmt_p2p_addrbook_record(B->book, A->idhex, &seq) != NULL && seq == 1);
    CHECK(!cmt_p2p_addrbook_is_banned(B->book, &aaddr));
    /* a change: not pushed again before ensurePeersPeriod */
    CHECK(make_rec(&A->id, &A->id, CHAIN_A, "20.0.3.1", 4004, 2, false, A->own_rec) == 0);
    cmt_p2p_pex_own_record_changed(A->pex);
    run(10, 100 * MS);
    CHECK(cmt_p2p_addrbook_record(B->book, A->idhex, &seq) != NULL && seq == 1);
    run(31, SEC);
    /* The re-push leaves on the first tick ≥ 30 s after push #1 (≈ the
     * 29th of these 1 s steps); it then needs a switch tick to be pumped
     * and two pipe passes, because its 5 sealed frames exceed the
     * receiver's 4-frame rbuf (CMT_P2P_CONN_RBUF_CAP) per pass. Drain it
     * with short steps. */
    run(50, 10 * MS);
    CHECK(cmt_p2p_addrbook_record(B->book, A->idhex, &seq) != NULL && seq == 2);
    CHECK(peer_of(B, A) != NULL);
    /* C pushes A's record: a foreign record → B stops C */
    CHECK(dial(C, B));
    run(100, 10 * MS);
    CHECK(peer_of(B, C) != NULL);
    CHECK(cmt_p2p_pex_marshal_push(A->own_rec, CMT_P2P_ADDR_REC_SIZE, buf, sizeof(buf),
                                   &n) == CMT_OK);
    CHECK(send_raw(C, B, buf, n));
    run(20, 10 * MS);
    CHECK(peer_of(B, C) == NULL && peer_of(B, A) != NULL);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("push");
    }
}

/* ══ 13. ensurePeers ═════════════════════════════════════════════════ */

static void test_pex_ensure_peers(void)
{
    node_params_t pc = { "20.0.4.1", 4004, 2, NULL };
    node_t *C, *D[4];
    cmt_p2p_netaddr_t caddr;
    int ok = 1, k, out = 0, in = 0, dialing = 0, dials_after;

    TEST("pex: ensurePeers dials max_num_outbound_peers from the book");
    C = node_new("C", &pc);
    for (k = 0; k < 4; k++) {
        static const char *ips[4] = { "20.0.4.11", "20.0.4.12", "20.0.4.13", "20.0.4.14" };
        node_params_t pd = { ips[k], 4004, 0, NULL };

        D[k] = node_new("D", &pd);
    }
    if (C == NULL || D[0] == NULL || D[1] == NULL || D[2] == NULL || D[3] == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    caddr = addr_of(C);
    for (k = 0; k < 4; k++) {
        cmt_p2p_netaddr_t d = addr_of(D[k]);

        CHECK(cmt_p2p_addrbook_add_address(C->book, &d, &caddr) == CMT_P2P_AB_OK);
        CHECK(node_start(D[k]));
    }
    CHECK(node_start(C));
    run(100, 10 * MS);                    /* the first ensurePeers (no jitter) */
    cmt_p2p_switch_num_peers(&C->sw, &out, &in, &dialing);
    CHECK(out >= 1 && out <= 2 && dialing == 0 && C->n_dials == out);
    run(70, SEC);                         /* two more ensurePeers periods */
    cmt_p2p_switch_num_peers(&C->sw, &out, &in, &dialing);
    dials_after = C->n_dials;
    CHECK(out == 2 && dialing == 0 && dials_after == 2);
    run(40, SEC);                         /* full: numToDial <= 0 (:456-458) */
    CHECK(C->n_dials == dials_after);
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("ensurePeers");
    }
}

/* ══ 14. a split answer ══════════════════════════════════════════════ */

#define N_SPLIT 21

static void test_pex_split(void)
{
    node_params_t pa = { "20.0.5.1", 4004, 0, NULL }, pb = { "20.0.5.2", 4004, 0, NULL };
    node_t *A, *B;
    uint8_t rec[CMT_P2P_ADDR_REC_SIZE];
    cmt_p2p_netaddr_t aaddr;
    int ok = 1, k, have = 0;

    TEST("pex: a 21-record answer (> 64 000 B) arrives whole, in parts");
    A = node_new("A", &pa);
    B = node_new("B", &pb);
    if (A == NULL || B == NULL) {
        FAIL("setup");
        world_reset();
        return;
    }
    aaddr = addr_of(A);
    for (k = 0; k < N_SPLIT; k++) {
        char ip[32];

        A->bonded.ids[A->bonded.n++] = &g_val[3 + k].id;
        B->bonded.ids[B->bonded.n++] = &g_val[3 + k].id;
        snprintf(ip, sizeof(ip), "50.0.%d.1", k + 1);
        if (make_rec(&g_val[3 + k].id, &g_val[3 + k].id, CHAIN_A, ip, 4004, 1, false, rec) != 0 ||
            cmt_p2p_addrbook_add_signed(A->book, NULL, &aaddr, rec, sizeof(rec), NULL) !=
            CMT_P2P_AB_OK) {
            ok = 0;
        }
    }
    CHECK(N_SPLIT * (CMT_P2P_PEX_REC_ELEM) > CMT_P2P_PEX_MAX_MSG_SIZE);
    CHECK(node_start(A) && node_start(B));
    settle();
    CHECK(dial(B, A));
    run(300, 10 * MS);
    CHECK(peer_of(B, A) != NULL && peer_of(A, B) != NULL);
    for (k = 0; k < N_SPLIT; k++) {
        uint64_t seq = 0;

        if (cmt_p2p_addrbook_record(B->book, g_val[3 + k].idhex, &seq) != NULL && seq == 1) {
            have++;
        }
    }
    CHECK(have == N_SPLIT);
    CHECK(!cmt_p2p_pex_request_outstanding(B->pex, A->idhex));
    CHECK(!cmt_p2p_addrbook_is_banned(B->book, &aaddr));
    world_reset();
    if (ok) {
        PASS();
    } else {
        FAIL("split");
    }
}

int main(void)
{
    int k;

    printf("test_p2p_pex — netaddress proto / address book / signed ADDR / PEX "
           "port (P2P-PORT F4)\n");
    g_val = (val_t *)calloc(3 + N_SPLIT, sizeof(val_t));
    if (g_val == NULL) {
        printf("memory\n");
        return 1;
    }
    for (k = 0; k < 3 + N_SPLIT; k++) {
        if (val_make(&g_val[k]) != 0) {
            printf("keygen failed\n");
            free(g_val);
            return 1;
        }
    }

    test_netaddr_proto();
    test_pex_codec();
    test_book_basic();
    test_book_buckets();
    test_book_selection();
    test_signed_addr();
    test_book_bans();
    test_own_record_echo();
    test_book_save_load();
    test_pex_round_trip_and_unsolicited();
    test_pex_request_flood();
    test_pex_private();
    test_pex_push();
    test_pex_ensure_peers();
    test_pex_split();

    free(g_val);
    printf("\n%d passed, %d failed\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
