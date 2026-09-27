/**
 * @file shared/dnac/cmt_p2p_addrbook.c
 * @brief cometbft @709fd12b `p2p/pex/addrbook.go`, `known_address.go`,
 *        `file.go` in C, plus the signed ADDR record (R-P2P-4).
 *
 * Contract, the record bytes and the deviations: cmt_p2p_addrbook.h.
 * Functions in the reference's order; each names its Go lines
 * (addrbook.go unless another file is named).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_p2p_addrbook.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_pb_wire.h"
#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_TAG "CMT_P2P_ADDRBOOK"

/* ══ known_address.go:11-20 — knownAddress ════════════════════════════ */

typedef struct ka {
    cmt_p2p_netaddr_t addr;                                /* :12 Addr */
    cmt_p2p_netaddr_t src;                                 /* :13 Src  */
    char     addr_str[CMT_P2P_NETADDR_STR_MAX];            /* Addr.String() */
    int      buckets[CMT_P2P_AB_MAX_NEW_BUCKETS_PER_ADDRESS]; /* :14 */
    int      n_buckets;
    int32_t  attempts;                                     /* :15 */
    uint8_t  bucket_type;                                  /* :16 */
    int64_t  last_attempt;                                 /* :17 */
    int64_t  last_success;                                 /* :18 */
    int64_t  last_ban_time;                                /* :19 */
    /* R-P2P-4 */
    uint8_t *rec;                                          /* payload ‖ sig */
    uint64_t seq;
    /* membership (the reference's GC owns the lifetime) */
    bool     in_lookup;
    bool     in_bad;
} ka_t;

typedef struct {
    ka_t *e[CMT_P2P_AB_BUCKET_CAP];
    int   n;
} bucket_t;

/* addrbook.go:88-110 addrBook */
struct cmt_p2p_addrbook {
    cmt_p2p_ab_config_t cfg;
    cmt_p2p_ab_host_t   host;
    char    key[CMT_P2P_AB_KEY_LEN + 1];                   /* :105 */
    uint8_t hkey[CMT_P2P_AB_HASH_KEY_LEN];                 /* :107 hasher */

    char  (*our)[CMT_P2P_NETADDR_STR_MAX];                 /* :94 ourAddrs */
    int     n_our;
    char  (*priv)[CMT_P2P_ID_CAP];                         /* :95 privateIDs */
    int     n_priv;
    ka_t  **lookup;                                        /* :96, sorted by ID */
    int     n_lookup, cap_lookup;
    ka_t  **bad;                                           /* :97 badPeers */
    int     n_bad, cap_bad;
    bucket_t bnew[CMT_P2P_AB_NEW_BUCKET_COUNT];            /* :99 */
    bucket_t bold[CMT_P2P_AB_OLD_BUCKET_COUNT];            /* :98 */
    int     n_old;                                         /* :100 */
    int     n_new;                                         /* :101 */

    bool    started;
    bool    stopped;
    bool    save_armed;
    int64_t next_save;

    bool     own_seen;
    uint64_t own_seq;
    /* The first record seen at own_seq (its bytes), and whether a
     * DIFFERENT record naming us was seen at that same seq (M1). */
    uint8_t  own_rec[CMT_P2P_ADDR_REC_SIZE];
    bool     own_rec_conflict;

    /* R-P2P-43 — received records whose signature check is in flight,
     * in submission order. */
    struct ab_pending *pend;
    int      n_pend;
    uint64_t next_ticket;
};

/* R-P2P-43 — one queued record (cmt_p2p_addrbook.h). */
typedef struct ab_pending {
    uint64_t          ticket;
    uint8_t           rec[CMT_P2P_ADDR_REC_SIZE];
    size_t            rec_len;
    bool              has_addr;
    cmt_p2p_netaddr_t addr;
    cmt_p2p_netaddr_t src;
    uint8_t           pk[QGP_DSA87_PUBLICKEYBYTES];   /* the key checked against */
    char              id[CMT_P2P_ID_CAP];
    uint64_t          seq;
} ab_pending_t;

/* ══ small helpers ════════════════════════════════════════════════════ */

static int64_t ab_now(const cmt_p2p_addrbook_t *a)
{
    return a->host.now_ns(a->host.ctx);
}

/* cmtrand Intn / rand.Int31n / Rand.Intn over the host (D4). */
static int64_t ab_rand(const cmt_p2p_addrbook_t *a, int64_t n)
{
    int64_t r;

    if (n <= 0) {
        return 0;
    }
    r = a->host.rand_int63n(a->host.ctx, n);
    return (r < 0 || r >= n) ? 0 : r;
}

/* Go math/rand Float64 (rand.go:187-199): a 53-bit fraction. */
static double ab_float64(const cmt_p2p_addrbook_t *a)
{
    return (double)ab_rand(a, (int64_t)1 << 53) / (double)((int64_t)1 << 53);
}

static void *grow(void *arr, int *cap, int n, size_t elem)
{
    if (n < *cap) {
        return arr;
    }
    {
        int ncap = *cap == 0 ? 16 : *cap * 2;
        void *na = realloc(arr, (size_t)ncap * elem);

        if (na == NULL) {
            return NULL;
        }
        *cap = ncap;
        return na;
    }
}

static ka_t *ka_new(const cmt_p2p_netaddr_t *addr, const cmt_p2p_netaddr_t *src,
                    int64_t now)
{
    ka_t *ka = (ka_t *)calloc(1, sizeof(*ka));             /* known_address.go:22-31 */

    if (ka == NULL) {
        return NULL;
    }
    ka->addr = *addr;
    ka->src = *src;
    (void)cmt_p2p_netaddr_string(&ka->addr, ka->addr_str, sizeof(ka->addr_str));
    ka->attempts = 0;
    ka->last_attempt = now;
    ka->bucket_type = CMT_P2P_AB_BUCKET_TYPE_NEW;
    ka->n_buckets = 0;
    ka->last_success = CMT_P2P_AB_TIME_ZERO;
    ka->last_ban_time = CMT_P2P_AB_TIME_ZERO;
    return ka;
}

static void ka_free(ka_t *ka)
{
    if (ka == NULL) {
        return;
    }
    free(ka->rec);
    free(ka);
}

/* The reference's garbage collector: an entry no map and no bucket holds
 * any more is freed. Called where the caller is done with it. */
static void ka_release(ka_t *ka)
{
    if (ka != NULL && !ka->in_lookup && !ka->in_bad && ka->n_buckets == 0) {
        ka_free(ka);
    }
}

static int ka_set_record(ka_t *ka, const uint8_t *rec, uint64_t seq)
{
    if (ka->rec == NULL) {
        ka->rec = (uint8_t *)malloc(CMT_P2P_ADDR_REC_SIZE);
        if (ka->rec == NULL) {
            return CMT_FAULT;
        }
    }
    memcpy(ka->rec, rec, CMT_P2P_ADDR_REC_SIZE);
    ka->seq = seq;
    return CMT_OK;
}

/* ── known_address.go ── */

static bool ka_is_old(const ka_t *ka)                      /* :37-39 */
{
    return ka != NULL && ka->bucket_type == CMT_P2P_AB_BUCKET_TYPE_OLD;
}

static bool ka_is_new(const ka_t *ka)                      /* :41-43 */
{
    return ka != NULL && ka->bucket_type == CMT_P2P_AB_BUCKET_TYPE_NEW;
}

static void ka_mark_attempt(ka_t *ka, int64_t now)         /* :45-49 */
{
    ka->last_attempt = now;
    ka->attempts++;
}

static void ka_mark_good(ka_t *ka, int64_t now)            /* :51-56 */
{
    ka->last_attempt = now;
    ka->attempts = 0;
    ka->last_success = now;
}

static void ka_ban(ka_t *ka, int64_t now, int64_t ban)     /* :58-62 */
{
    if (ka->last_ban_time < now + ban) {
        ka->last_ban_time = now + ban;
    }
}

static bool ka_is_banned(const ka_t *ka, int64_t now)      /* :64-66 */
{
    return ka->last_ban_time > now;
}

static bool ka_has_bucket_ref(const ka_t *ka, int idx)
{
    int i;

    for (i = 0; i < ka->n_buckets; i++) {
        if (ka->buckets[i] == idx) {
            return true;
        }
    }
    return false;
}

/* :68-78 addBucketRef. The caller has checked the storage bound
 * (CMT_P2P_AB_MAX_NEW_BUCKETS_PER_ADDRESS — never reached: :683-685). */
static int ka_add_bucket_ref(ka_t *ka, int idx)
{
    if (ka_has_bucket_ref(ka, idx)) {
        return -1;                                         /* :69-75 */
    }
    ka->buckets[ka->n_buckets++] = idx;                    /* :76 */
    return ka->n_buckets;
}

static int ka_remove_bucket_ref(ka_t *ka, int idx)         /* :80-94 */
{
    int i;

    for (i = 0; i < ka->n_buckets; i++) {
        if (ka->buckets[i] == idx) {
            memmove(&ka->buckets[i], &ka->buckets[i + 1],
                    (size_t)(ka->n_buckets - i - 1) * sizeof(ka->buckets[0]));
            ka->n_buckets--;
            return ka->n_buckets;
        }
    }
    return -1;
}

/* :108-139 isBad */
static bool ka_is_bad(const ka_t *ka, int64_t now)
{
    if (ka->bucket_type == CMT_P2P_AB_BUCKET_TYPE_OLD) {
        return false;                                      /* :110-112 */
    }
    if (ka->last_attempt > now - 60LL * CMT_P2P_AB_NS_PER_SEC) {
        return false;                                      /* :115-117 */
    }
    if (ka->last_attempt < now - CMT_P2P_AB_NUM_MISSING_DAYS * CMT_P2P_AB_NS_PER_DAY) {
        return true;                                       /* :123-125 */
    }
    if (ka->last_success == CMT_P2P_AB_TIME_ZERO &&
        ka->attempts >= CMT_P2P_AB_NUM_RETRIES) {
        return true;                                       /* :128-130 */
    }
    if (ka->last_success < now - CMT_P2P_AB_MIN_BAD_DAYS * CMT_P2P_AB_NS_PER_DAY &&
        ka->attempts >= CMT_P2P_AB_MAX_FAILURES) {
        return true;                                       /* :133-136 */
    }
    return false;
}

/* ── the maps as arrays (R-P2P-36) ── */

static int lookup_index(const cmt_p2p_addrbook_t *a, const char *id, bool *found)
{
    int lo = 0, hi = a->n_lookup;

    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        int c = strcmp(a->lookup[mid]->addr.id, id);

        if (c == 0) {
            *found = true;
            return mid;
        }
        if (c < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    *found = false;
    return lo;
}

static ka_t *lookup_get(const cmt_p2p_addrbook_t *a, const char *id)
{
    bool found;
    int i;

    if (id == NULL) {
        return NULL;
    }
    i = lookup_index(a, id, &found);
    return found ? a->lookup[i] : NULL;
}

/* Room for one more lookup entry, taken BEFORE a bucket is touched so
 * that `lookup_put` cannot fail half-way through an insertion. */
static int lookup_reserve(cmt_p2p_addrbook_t *a)
{
    void *na = grow(a->lookup, &a->cap_lookup, a->n_lookup, sizeof(*a->lookup));

    if (na == NULL) {
        return CMT_FAULT;
    }
    a->lookup = (ka_t **)na;
    return CMT_OK;
}

/* addrLookup[ka.ID()] = ka — after `lookup_reserve`. */
static int lookup_put(cmt_p2p_addrbook_t *a, ka_t *ka)
{
    bool found;
    int i = lookup_index(a, ka->addr.id, &found);

    if (found) {
        if (a->lookup[i] != ka) {
            QGP_LOG_ERROR(LOG_TAG, "two entries for ID %s", ka->addr.id);
            a->lookup[i]->in_lookup = false;
            a->lookup[i] = ka;
        }
        ka->in_lookup = true;
        return CMT_OK;
    }
    if (lookup_reserve(a) != CMT_OK) {
        return CMT_FAULT;
    }
    memmove(&a->lookup[i + 1], &a->lookup[i],
            (size_t)(a->n_lookup - i) * sizeof(*a->lookup));
    a->lookup[i] = ka;
    a->n_lookup++;
    ka->in_lookup = true;
    return CMT_OK;
}

/* delete(a.addrLookup, id) */
static void lookup_delete(cmt_p2p_addrbook_t *a, const char *id)
{
    bool found;
    int i = lookup_index(a, id, &found);

    if (!found) {
        return;
    }
    a->lookup[i]->in_lookup = false;
    memmove(&a->lookup[i], &a->lookup[i + 1],
            (size_t)(a->n_lookup - i - 1) * sizeof(*a->lookup));
    a->n_lookup--;
}

/* The ban list, `a.badPeers` (addrbook.go:97, a map keyed by ID, with no
 * size bound — :820-825 adds without a limit), is an array SORTED BY ID
 * like `lookup` (R-P2P-36): membership is a binary search, O(log n)
 * (red-team M5; it was a linear strcmp scan). No bound is added, as in
 * the reference. @return the index where `id` is or would be inserted;
 * `*found` says which. */
static int bad_search(const cmt_p2p_addrbook_t *a, const char *id, bool *found)
{
    int lo = 0, hi = a->n_bad;

    while (lo < hi) {
        int mid = lo + (hi - lo) / 2;
        int c = strcmp(a->bad[mid]->addr.id, id);

        if (c == 0) {
            *found = true;
            return mid;
        }
        if (c < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    *found = false;
    return lo;
}

static int bad_index(const cmt_p2p_addrbook_t *a, const char *id)
{
    bool found;
    int i = bad_search(a, id, &found);

    return found ? i : -1;
}

static void bad_delete_at(cmt_p2p_addrbook_t *a, int i)
{
    a->bad[i]->in_bad = false;
    memmove(&a->bad[i], &a->bad[i + 1], (size_t)(a->n_bad - i - 1) * sizeof(*a->bad));
    a->n_bad--;
}

static bool is_private_id(const cmt_p2p_addrbook_t *a, const char *id)
{
    int i;

    for (i = 0; i < a->n_priv; i++) {
        if (strcmp(a->priv[i], id) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_our(const cmt_p2p_addrbook_t *a, const char *addr_str)
{
    int i;

    for (i = 0; i < a->n_our; i++) {
        if (strcmp(a->our[i], addr_str) == 0) {
            return true;
        }
    }
    return false;
}

static int bucket_find(const bucket_t *b, const char *addr_str)
{
    int i;

    for (i = 0; i < b->n; i++) {
        if (strcmp(b->e[i]->addr_str, addr_str) == 0) {
            return i;
        }
    }
    return -1;
}

static void bucket_delete(bucket_t *b, const char *addr_str)
{
    int i = bucket_find(b, addr_str);

    if (i < 0) {
        return;
    }
    memmove(&b->e[i], &b->e[i + 1], (size_t)(b->n - i - 1) * sizeof(b->e[0]));
    b->n--;
}

/* ══ the signed ADDR record (R-P2P-4) ═════════════════════════════════ */

int cmt_p2p_addr_rec_payload(const uint8_t chain_id[CMT_P2P_ADDR_REC_CHAIN_LEN],
                             const uint8_t pk_fp[CMT_P2P_ADDR_REC_FP_LEN],
                             const cmt_p2p_ip_t *ip, uint16_t port,
                             uint64_t seq,
                             uint8_t out[CMT_P2P_ADDR_REC_PAYLOAD_SIZE])
{
    uint8_t *p = out;
    uint8_t v4[4];
    int i;

    if (chain_id == NULL || pk_fp == NULL || ip == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (ip->len != CMT_P2P_IPV4_LEN && ip->len != CMT_P2P_IPV6_LEN) {
        return CMT_REJECT;
    }
    memcpy(p, CMT_P2P_ADDR_REC_TAG, CMT_P2P_ADDR_REC_TAG_LEN);
    p += CMT_P2P_ADDR_REC_TAG_LEN;
    memcpy(p, chain_id, CMT_P2P_ADDR_REC_CHAIN_LEN);
    p += CMT_P2P_ADDR_REC_CHAIN_LEN;
    memcpy(p, pk_fp, CMT_P2P_ADDR_REC_FP_LEN);
    p += CMT_P2P_ADDR_REC_FP_LEN;
    if (cmt_p2p_ip_to4(ip, v4)) {                          /* ::ffff:a.b.c.d */
        memset(p, 0, 10);
        p[10] = 0xff;
        p[11] = 0xff;
        memcpy(p + 12, v4, 4);
    } else {
        memcpy(p, ip->b, CMT_P2P_ADDR_REC_IP_LEN);
    }
    p += CMT_P2P_ADDR_REC_IP_LEN;
    p[0] = (uint8_t)(port >> 8);
    p[1] = (uint8_t)port;
    p += 2;
    for (i = 0; i < 8; i++) {
        p[i] = (uint8_t)(seq >> (56 - 8 * i));
    }
    return CMT_OK;
}

int cmt_p2p_addr_rec_parse(const uint8_t *rec, size_t len,
                           cmt_p2p_addr_rec_t *out)
{
    const uint8_t *p = rec;
    int i;

    if (rec == NULL || out == NULL) {
        return CMT_FAULT;
    }
    if (len != CMT_P2P_ADDR_REC_SIZE ||
        memcmp(p, CMT_P2P_ADDR_REC_TAG, CMT_P2P_ADDR_REC_TAG_LEN) != 0) {
        return CMT_REJECT;
    }
    memset(out, 0, sizeof(*out));
    p += CMT_P2P_ADDR_REC_TAG_LEN;
    memcpy(out->chain_id, p, CMT_P2P_ADDR_REC_CHAIN_LEN);
    p += CMT_P2P_ADDR_REC_CHAIN_LEN;
    memcpy(out->pk_fp, p, CMT_P2P_ADDR_REC_FP_LEN);
    p += CMT_P2P_ADDR_REC_FP_LEN;
    memcpy(out->ip.b, p, CMT_P2P_ADDR_REC_IP_LEN);
    out->ip.len = CMT_P2P_IPV6_LEN;
    p += CMT_P2P_ADDR_REC_IP_LEN;
    out->port = (uint16_t)(((unsigned)p[0] << 8) | p[1]);
    p += 2;
    out->seq = 0;
    for (i = 0; i < 8; i++) {
        out->seq = (out->seq << 8) | p[i];
    }
    for (i = 0; i < CMT_P2P_ID_BYTE_LENGTH; i++) {         /* key.go:44 */
        static const char hx[] = "0123456789abcdef";

        out->id[2 * i] = hx[out->pk_fp[i] >> 4];
        out->id[2 * i + 1] = hx[out->pk_fp[i] & 0x0f];
    }
    out->id[CMT_P2P_ID_HEX_LEN] = '\0';
    return CMT_OK;
}

const char *cmt_p2p_ab_err_str(int err)
{
    switch (err) {
    case CMT_P2P_AB_OK:                    return "ok";
    case CMT_P2P_AB_ERR_NIL_ADDR:          return "cannot add a nil address";
    case CMT_P2P_AB_ERR_INVALID_ADDR:      return "cannot add invalid address";
    case CMT_P2P_AB_ERR_BANNED:            return "address is currently banned";
    case CMT_P2P_AB_ERR_PRIVATE:           return "cannot add private peer";
    case CMT_P2P_AB_ERR_PRIVATE_SRC:       return "cannot add peer coming from private peer";
    case CMT_P2P_AB_ERR_SELF:              return "cannot add ourselves";
    case CMT_P2P_AB_ERR_NON_ROUTABLE:      return "cannot add non-routable address";
    case CMT_P2P_AB_ERR_OLD_ADDRESS_NEW_BUCKET: return "cannot add pre-existing address into new bucket";
    case CMT_P2P_AB_ERR_UNSIGNED_BONDED:   return "bonded identity without a signed record";
    case CMT_P2P_AB_ERR_NOT_BONDED:        return "record for an identity that is not bonded";
    case CMT_P2P_AB_ERR_RECORD_MALFORMED:  return "malformed ADDR record";
    case CMT_P2P_AB_ERR_RECORD_CHAIN:      return "ADDR record for another chain";
    case CMT_P2P_AB_ERR_RECORD_KEY:        return "ADDR record key does not match the chain";
    case CMT_P2P_AB_ERR_RECORD_SIG:        return "ADDR record signature invalid";
    case CMT_P2P_AB_ERR_RECORD_MISMATCH:   return "ADDR record does not name this address";
    case CMT_P2P_AB_ERR_RECORD_NOT_NEWER:  return "ADDR record is not newer";
    case CMT_P2P_AB_PENDING:               return "ADDR record signature check queued";
    case CMT_P2P_AB_ERR_VERIFY_QUEUE_FULL: return "ADDR record verification queue full";
    default:                               return "unknown";
    }
}

/* Every check a record gets before the book believes it (file header),
 * except the signature: the chain key it must verify under goes to `pk`. */
static int rec_prechecks(cmt_p2p_addrbook_t *a, const uint8_t *rec, size_t len,
                         cmt_p2p_addr_rec_t *r,
                         uint8_t pk[QGP_DSA87_PUBLICKEYBYTES])
{
    uint8_t fp[QGP_SHA3_512_DIGEST_LENGTH];

    if (cmt_p2p_addr_rec_parse(rec, len, r) != CMT_OK) {
        return CMT_P2P_AB_ERR_RECORD_MALFORMED;
    }
    if (memcmp(r->chain_id, a->cfg.chain_id, CMT_P2P_ADDR_REC_CHAIN_LEN) != 0) {
        return CMT_P2P_AB_ERR_RECORD_CHAIN;
    }
    if (a->host.bonded_pubkey == NULL ||
        !a->host.bonded_pubkey(a->host.ctx, r->id, pk)) {
        return CMT_P2P_AB_ERR_NOT_BONDED;
    }
    if (qgp_sha3_512(pk, QGP_DSA87_PUBLICKEYBYTES, fp) != 0 ||
        memcmp(fp, r->pk_fp, sizeof(fp)) != 0) {
        return CMT_P2P_AB_ERR_RECORD_KEY;
    }
    return CMT_P2P_AB_OK;
}

/* The 0x0B signature, synchronously (load, and a host with no worker). */
static int rec_sig_sync(cmt_p2p_addrbook_t *a, const uint8_t *rec,
                        const uint8_t pk[QGP_DSA87_PUBLICKEYBYTES])
{
    if (a->host.verify_addr == NULL ||
        a->host.verify_addr(a->host.ctx, rec, CMT_P2P_ADDR_REC_PAYLOAD_SIZE,
                            rec + CMT_P2P_ADDR_REC_PAYLOAD_SIZE, pk) != 0) {
        return CMT_P2P_AB_ERR_RECORD_SIG;
    }
    return CMT_P2P_AB_OK;
}

/* Every check a record gets before the book believes it — synchronously. */
static int rec_verify(cmt_p2p_addrbook_t *a, const uint8_t *rec, size_t len,
                      cmt_p2p_addr_rec_t *r)
{
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    int rc = rec_prechecks(a, rec, len, r, pk);

    return rc != CMT_P2P_AB_OK ? rc : rec_sig_sync(a, rec, pk);
}

static bool is_bonded(const cmt_p2p_addrbook_t *a, const char *id)
{
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];

    return a->host.bonded_pubkey != NULL &&
           a->host.bonded_pubkey(a->host.ctx, id, pk);
}

/* ══ construction and service (:121-181) ══════════════════════════════ */

/* :140-153 init — both keys. */
static int ab_init_keys(cmt_p2p_addrbook_t *a)
{
    uint8_t rb[CMT_P2P_AB_KEY_LEN / 2];
    static const char hx[] = "0123456789abcdef";
    int i;

    if (a->host.rand_bytes(a->host.ctx, rb, sizeof(rb)) != 0 ||      /* :141 */
        a->host.rand_bytes(a->host.ctx, a->hkey, sizeof(a->hkey)) != 0) { /* :113 */
        return CMT_FAULT;
    }
    for (i = 0; i < (int)sizeof(rb); i++) {
        a->key[2 * i] = hx[rb[i] >> 4];
        a->key[2 * i + 1] = hx[rb[i] & 0x0f];
    }
    a->key[CMT_P2P_AB_KEY_LEN] = '\0';
    return CMT_OK;
}

/* :123-136 NewAddrBook */
cmt_p2p_addrbook_t *cmt_p2p_addrbook_new(const cmt_p2p_ab_config_t *cfg,
                                         const cmt_p2p_ab_host_t *host)
{
    cmt_p2p_addrbook_t *a;

    if (cfg == NULL || host == NULL || host->now_ns == NULL ||
        host->rand_bytes == NULL || host->rand_int63n == NULL ||
        (host->bonded_pubkey != NULL && host->verify_addr == NULL)) {
        return NULL;
    }
    a = (cmt_p2p_addrbook_t *)calloc(1, sizeof(*a));
    if (a == NULL) {
        return NULL;
    }
    a->cfg = *cfg;
    a->cfg.self_id[CMT_P2P_ID_CAP - 1] = '\0';
    a->host = *host;
    if (ab_init_keys(a) != CMT_OK) {
        free(a);
        return NULL;
    }
    return a;
}

void cmt_p2p_addrbook_free(cmt_p2p_addrbook_t *a)
{
    int i, b;

    if (a == NULL) {
        return;
    }
    /* Every entry is in the lookup, in bad, or both — detach, then free. */
    for (b = 0; b < CMT_P2P_AB_NEW_BUCKET_COUNT; b++) {
        a->bnew[b].n = 0;
    }
    for (b = 0; b < CMT_P2P_AB_OLD_BUCKET_COUNT; b++) {
        a->bold[b].n = 0;
    }
    for (i = 0; i < a->n_lookup; i++) {
        ka_t *ka = a->lookup[i];

        ka->in_lookup = false;
        ka->n_buckets = 0;
        if (!ka->in_bad) {
            ka_free(ka);
        }
    }
    for (i = 0; i < a->n_bad; i++) {
        ka_free(a->bad[i]);
    }
    free(a->lookup);
    free(a->bad);
    free(a->our);
    free(a->priv);
    free(a->pend);
    memset(a->hkey, 0, sizeof(a->hkey));
    free(a);
}

static int load_from_file(cmt_p2p_addrbook_t *a);
static void save_to_file(cmt_p2p_addrbook_t *a);

/* :156-168 OnStart */
int cmt_p2p_addrbook_start(cmt_p2p_addrbook_t *a)
{
    int rc;

    if (a == NULL) {
        return CMT_FAULT;
    }
    if (a->started) {
        return CMT_OK;                    /* ErrAlreadyStarted, ignored by PEX */
    }
    rc = load_from_file(a);                                /* :160 */
    if (rc != CMT_OK) {
        return rc;
    }
    a->started = true;                                     /* :164-165 saveRoutine */
    a->save_armed = false;
    return CMT_OK;
}

/* :171-173 OnStop + saveRoutine's exit (:510-511) */
void cmt_p2p_addrbook_stop(cmt_p2p_addrbook_t *a)
{
    if (a == NULL || !a->started || a->stopped) {
        return;
    }
    a->stopped = true;
    save_to_file(a);
}

/* :497-509 saveRoutine's ticker */
void cmt_p2p_addrbook_tick(cmt_p2p_addrbook_t *a, int64_t mono_now_ns)
{
    if (a == NULL || !a->started || a->stopped) {
        return;
    }
    if (!a->save_armed) {
        a->save_armed = true;
        a->next_save = mono_now_ns + CMT_P2P_AB_DUMP_ADDRESS_INTERVAL_NS;
        return;
    }
    if (mono_now_ns >= a->next_save) {
        save_to_file(a);                                   /* :504-505 */
        a->next_save = mono_now_ns + CMT_P2P_AB_DUMP_ADDRESS_INTERVAL_NS;
    }
}

/* ══ bucket placement (:829-947) ══════════════════════════════════════ */

/* :943-947 hash — R-P2P-34: SHA3-512(hasher_key ‖ b), first 8 bytes. */
static bool ab_hash(const cmt_p2p_addrbook_t *a, const uint8_t *b, size_t n,
                    uint64_t *out)
{
    uint8_t buf[CMT_P2P_AB_HASH_KEY_LEN + 512];
    uint8_t d[QGP_SHA3_512_DIGEST_LENGTH];
    int i;

    if (n > sizeof(buf) - CMT_P2P_AB_HASH_KEY_LEN) {
        return false;
    }
    memcpy(buf, a->hkey, CMT_P2P_AB_HASH_KEY_LEN);
    memcpy(buf + CMT_P2P_AB_HASH_KEY_LEN, b, n);
    if (qgp_sha3_512(buf, CMT_P2P_AB_HASH_KEY_LEN + n, d) != 0) {
        return false;
    }
    *out = 0;
    for (i = 0; i < 8; i++) {
        *out = (*out << 8) | d[i];                         /* BigEndian.Uint64 */
    }
    return true;
}

/* Go `net.IP(4 bytes).Mask(CIDRMask(16, 32)).String()`. */
static size_t v4_slash16(const uint8_t v4[4], char *out, size_t cap)
{
    cmt_p2p_ip_t m = cmt_p2p_ip_v4(v4[0], v4[1], 0, 0);

    return cmt_p2p_ip_string(&m, out, cap);
}

/* :893-941 groupKeyFor */
size_t cmt_p2p_addrbook_group_key(const cmt_p2p_netaddr_t *na, bool strict,
                                  char *out, size_t cap)
{
    uint8_t v4[4];
    int n;

    if (na == NULL || out == NULL || cap == 0) {
        return 0;
    }
    if (strict && cmt_p2p_netaddr_local(na)) {             /* :894-896 */
        n = snprintf(out, cap, "local");
        return (n < 0 || (size_t)n >= cap) ? 0 : (size_t)n;
    }
    if (strict && !cmt_p2p_netaddr_routable(na)) {         /* :897-899 */
        n = snprintf(out, cap, "unroutable");
        return (n < 0 || (size_t)n >= cap) ? 0 : (size_t)n;
    }
    if (cmt_p2p_ip_to4(&na->ip, v4)) {                     /* :901-903 */
        return v4_slash16(v4, out, cap);
    }
    if (na->ip.len != CMT_P2P_IPV6_LEN) {
        /* a nil IP: Mask returns nil, whose String is "<nil>" */
        n = snprintf(out, cap, "<nil>");
        return (n < 0 || (size_t)n >= cap) ? 0 : (size_t)n;
    }
    if (cmt_p2p_netaddr_rfc6145(na) || cmt_p2p_netaddr_rfc6052(na)) {
        return v4_slash16(na->ip.b + 12, out, cap);        /* :905-909 */
    }
    if (cmt_p2p_netaddr_rfc3964(na)) {
        return v4_slash16(na->ip.b + 2, out, cap);         /* :911-914 */
    }
    if (cmt_p2p_netaddr_rfc4380(na)) {                     /* :916-924 */
        uint8_t x[4];
        int i;

        for (i = 0; i < 4; i++) {
            x[i] = na->ip.b[12 + i] ^ 0xff;
        }
        return v4_slash16(x, out, cap);
    }
    if (cmt_p2p_netaddr_onion_cat_tor(na)) {               /* :926-929 */
        n = snprintf(out, cap, "tor:%d", na->ip.b[6] & ((1 << 4) - 1));
        return (n < 0 || (size_t)n >= cap) ? 0 : (size_t)n;
    }
    {                                                      /* :934-940 */
        static const uint8_t he_net[4] = { 0x20, 0x01, 0x04, 0x70 };
        int bits = memcmp(na->ip.b, he_net, 4) == 0 ? 36 : 32;
        cmt_p2p_ip_t m;
        int i;

        memset(&m, 0, sizeof(m));
        m.len = CMT_P2P_IPV6_LEN;
        for (i = 0; i < 16; i++) {
            int keep = bits - 8 * i;

            if (keep >= 8) {
                m.b[i] = na->ip.b[i];
            } else if (keep > 0) {
                m.b[i] = (uint8_t)(na->ip.b[i] & (uint8_t)(0xff << (8 - keep)));
            }
        }
        return cmt_p2p_ip_string(&m, out, cap);
    }
}

typedef struct {
    uint8_t b[512];
    size_t  n;
    bool    ok;
} hbuf_t;

static void hb_put(hbuf_t *h, const void *p, size_t n)
{
    if (!h->ok || n > sizeof(h->b) - h->n) {
        h->ok = false;
        return;
    }
    memcpy(h->b + h->n, p, n);
    h->n += n;
}

static void hb_str(hbuf_t *h, const char *s)
{
    hb_put(h, s, strlen(s));
}

static void hb_group(hbuf_t *h, const cmt_p2p_addrbook_t *a,
                     const cmt_p2p_netaddr_t *na)
{
    char g[CMT_P2P_NETADDR_STR_MAX];

    if (cmt_p2p_addrbook_group_key(na, a->cfg.routability_strict, g,
                                   sizeof(g)) == 0) {
        h->ok = false;
        return;
    }
    hb_str(h, g);
}

static void hb_u64be(hbuf_t *h, uint64_t v)
{
    uint8_t b[8];
    int i;

    for (i = 0; i < 8; i++) {
        b[i] = (uint8_t)(v >> (56 - 8 * i));
    }
    hb_put(h, b, 8);
}

/* :833-857 calcNewBucket */
int cmt_p2p_addrbook_calc_new_bucket(const cmt_p2p_addrbook_t *a,
                                     const cmt_p2p_netaddr_t *addr,
                                     const cmt_p2p_netaddr_t *src)
{
    hbuf_t h;
    uint64_t h1, h2;

    if (a == NULL || addr == NULL || src == NULL) {
        return -1;
    }
    h.n = 0;
    h.ok = true;
    hb_str(&h, a->key);                                    /* :835 */
    hb_group(&h, a, addr);                                 /* :836 */
    hb_group(&h, a, src);                                  /* :837 */
    if (!h.ok || !ab_hash(a, h.b, h.n, &h1)) {
        return -1;
    }
    h1 %= CMT_P2P_AB_NEW_BUCKETS_PER_GROUP;                /* :843 */
    h.n = 0;
    hb_str(&h, a->key);                                    /* :847 */
    hb_group(&h, a, src);                                  /* :848 */
    hb_u64be(&h, h1);                                      /* :849 */
    if (!h.ok || !ab_hash(a, h.b, h.n, &h2)) {
        return -1;
    }
    return (int)(h2 % CMT_P2P_AB_NEW_BUCKET_COUNT);        /* :855 */
}

/* :860-883 calcOldBucket */
int cmt_p2p_addrbook_calc_old_bucket(const cmt_p2p_addrbook_t *a,
                                     const cmt_p2p_netaddr_t *addr)
{
    char s[CMT_P2P_NETADDR_STR_MAX];
    hbuf_t h;
    uint64_t h1, h2;

    if (a == NULL || addr == NULL) {
        return -1;
    }
    (void)cmt_p2p_netaddr_string(addr, s, sizeof(s));
    h.n = 0;
    h.ok = true;
    hb_str(&h, a->key);                                    /* :862 */
    hb_str(&h, s);                                         /* :863 */
    if (!h.ok || !ab_hash(a, h.b, h.n, &h1)) {
        return -1;
    }
    h1 %= CMT_P2P_AB_OLD_BUCKETS_PER_GROUP;                /* :869 */
    h.n = 0;
    hb_str(&h, a->key);                                    /* :873 */
    hb_group(&h, a, addr);                                 /* :874 */
    hb_u64be(&h, h1);                                      /* :875 */
    if (!h.ok || !ab_hash(a, h.b, h.n, &h2)) {
        return -1;
    }
    return (int)(h2 % CMT_P2P_AB_OLD_BUCKET_COUNT);        /* :881 */
}

/* ══ bucket operations (:516-627) ═════════════════════════════════════ */

static bucket_t *get_bucket(cmt_p2p_addrbook_t *a, uint8_t type, int idx)
{
    if (type == CMT_P2P_AB_BUCKET_TYPE_NEW && idx >= 0 &&
        idx < CMT_P2P_AB_NEW_BUCKET_COUNT) {
        return &a->bnew[idx];
    }
    if (type == CMT_P2P_AB_BUCKET_TYPE_OLD && idx >= 0 &&
        idx < CMT_P2P_AB_OLD_BUCKET_COUNT) {
        return &a->bold[idx];
    }
    return NULL;                         /* :522-523 panics; never reached */
}

static void expire_new(cmt_p2p_addrbook_t *a, int idx);

/* :529-559 addToNewBucket */
static int add_to_new_bucket(cmt_p2p_addrbook_t *a, ka_t *ka, int idx)
{
    bucket_t *b;

    if (ka_is_old(ka)) {
        return CMT_P2P_AB_ERR_OLD_ADDRESS_NEW_BUCKET;      /* :531-533 */
    }
    b = get_bucket(a, CMT_P2P_AB_BUCKET_TYPE_NEW, idx);
    if (b == NULL) {
        return CMT_FAULT;
    }
    if (bucket_find(b, ka->addr_str) >= 0) {
        return CMT_P2P_AB_OK;                              /* :539-541 */
    }
    if (b->n > CMT_P2P_AB_NEW_BUCKET_SIZE) {               /* :544-547 */
        QGP_LOG_INFO(LOG_TAG, "new bucket is full, expiring new");
        expire_new(a, idx);
    }
    /* storage bounds (expire_new made room; :683-685 caps the refs) */
    if (b->n >= CMT_P2P_AB_BUCKET_CAP ||
        (!ka_has_bucket_ref(ka, idx) &&
         ka->n_buckets >= CMT_P2P_AB_MAX_NEW_BUCKETS_PER_ADDRESS) ||
        lookup_reserve(a) != CMT_OK) {
        return CMT_FAULT;
    }
    b->e[b->n++] = ka;                                     /* :550 */
    if (ka_add_bucket_ref(ka, idx) == 1) {
        a->n_new++;                                        /* :552-554 */
    }
    return lookup_put(a, ka);                              /* :557 */
}

/* :562-596 addToOldBucket */
static bool add_to_old_bucket(cmt_p2p_addrbook_t *a, ka_t *ka, int idx)
{
    bucket_t *b;

    if (ka_is_new(ka)) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot add new address to old bucket: %s", ka->addr_str);
        return false;                                      /* :564-567 */
    }
    if (ka->n_buckets != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot add already old address to another old "
                      "bucket: %s", ka->addr_str);
        return false;                                      /* :568-571 */
    }
    b = get_bucket(a, CMT_P2P_AB_BUCKET_TYPE_OLD, idx);
    if (b == NULL) {
        return false;
    }
    if (bucket_find(b, ka->addr_str) >= 0) {
        return true;                                       /* :577-579 */
    }
    if (b->n > CMT_P2P_AB_OLD_BUCKET_SIZE) {
        return false;                                      /* :582-584 */
    }
    if (lookup_reserve(a) != CMT_OK) {
        return false;
    }
    b->e[b->n++] = ka;                                     /* :587 */
    if (ka_add_bucket_ref(ka, idx) == 1) {
        a->n_old++;                                        /* :588-590 */
    }
    return lookup_put(a, ka) == CMT_OK;                    /* :593 */
}

/* :598-613 removeFromBucket */
static void remove_from_bucket(cmt_p2p_addrbook_t *a, ka_t *ka, uint8_t type,
                               int idx)
{
    bucket_t *b;

    if (ka->bucket_type != type) {
        QGP_LOG_ERROR(LOG_TAG, "Bucket type mismatch: %s", ka->addr_str);
        return;                                            /* :599-602 */
    }
    b = get_bucket(a, type, idx);
    if (b == NULL) {
        return;
    }
    bucket_delete(b, ka->addr_str);                        /* :604 */
    if (ka_remove_bucket_ref(ka, idx) == 0) {              /* :605-612 */
        if (type == CMT_P2P_AB_BUCKET_TYPE_NEW) {
            a->n_new--;
        } else {
            a->n_old--;
        }
        lookup_delete(a, ka->addr.id);
    }
}

/* :615-627 removeFromAllBuckets */
static void remove_from_all_buckets(cmt_p2p_addrbook_t *a, ka_t *ka)
{
    int i;

    for (i = 0; i < ka->n_buckets; i++) {
        bucket_t *b = get_bucket(a, ka->bucket_type, ka->buckets[i]);

        if (b != NULL) {
            bucket_delete(b, ka->addr_str);
        }
    }
    ka->n_buckets = 0;                                     /* :620 */
    if (ka->bucket_type == CMT_P2P_AB_BUCKET_TYPE_NEW) {
        a->n_new--;
    } else {
        a->n_old--;
    }
    lookup_delete(a, ka->addr.id);                         /* :626 */
}

/* :631-640 pickOldest */
static ka_t *pick_oldest(cmt_p2p_addrbook_t *a, uint8_t type, int idx)
{
    bucket_t *b = get_bucket(a, type, idx);
    ka_t *oldest = NULL;
    int i;

    if (b == NULL) {
        return NULL;
    }
    for (i = 0; i < b->n; i++) {
        if (oldest == NULL || b->e[i]->last_attempt < oldest->last_attempt) {
            oldest = b->e[i];
        }
    }
    return oldest;
}

/* :742-755 expireNew */
static void expire_new(cmt_p2p_addrbook_t *a, int idx)
{
    bucket_t *b = &a->bnew[idx];
    int64_t now = ab_now(a);
    ka_t *oldest;
    int i;

    for (i = 0; i < b->n; i++) {
        ka_t *ka = b->e[i];

        if (ka_is_bad(ka, now)) {                          /* :744-749 */
            QGP_LOG_INFO(LOG_TAG, "expiring bad address %s", ka->addr_str);
            remove_from_bucket(a, ka, CMT_P2P_AB_BUCKET_TYPE_NEW, idx);
            ka_release(ka);
            return;
        }
    }
    oldest = pick_oldest(a, CMT_P2P_AB_BUCKET_TYPE_NEW, idx);   /* :753-754 */
    if (oldest != NULL) {
        remove_from_bucket(a, oldest, CMT_P2P_AB_BUCKET_TYPE_NEW, idx);
        ka_release(oldest);
    }
}

/* :760-801 moveToOld */
static int move_to_old(cmt_p2p_addrbook_t *a, ka_t *ka)
{
    int old_idx;
    bool added;

    if (ka_is_old(ka)) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot promote address that is already old %s",
                      ka->addr_str);
        return CMT_OK;                                     /* :762-765 */
    }
    if (ka->n_buckets == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Cannot promote address that isn't in any new "
                      "buckets %s", ka->addr_str);
        return CMT_OK;                                     /* :766-769 */
    }
    remove_from_all_buckets(a, ka);                        /* :772 */
    ka->bucket_type = CMT_P2P_AB_BUCKET_TYPE_OLD;          /* :774 */
    old_idx = cmt_p2p_addrbook_calc_old_bucket(a, &ka->addr);   /* :777 */
    if (old_idx < 0) {
        ka_release(ka);
        return CMT_FAULT;
    }
    added = add_to_old_bucket(a, ka, old_idx);             /* :781 */
    if (!added) {
        ka_t *oldest = pick_oldest(a, CMT_P2P_AB_BUCKET_TYPE_OLD, old_idx);  /* :784 */

        if (oldest != NULL) {
            int new_idx;

            remove_from_bucket(a, oldest, CMT_P2P_AB_BUCKET_TYPE_OLD, old_idx); /* :785 */
            new_idx = cmt_p2p_addrbook_calc_new_bucket(a, &oldest->addr,
                                                       &oldest->src);       /* :786 */
            if (new_idx < 0) {
                ka_release(oldest);
                ka_release(ka);
                return CMT_FAULT;
            }
            /* :790-792 — `oldest` is still of the OLD type here, so the
             * reference's addToNewBucket refuses it and it is dropped. */
            if (add_to_new_bucket(a, oldest, new_idx) != CMT_P2P_AB_OK) {
                QGP_LOG_ERROR(LOG_TAG, "Error adding peer to old bucket");
            }
            ka_release(oldest);
        }
        added = add_to_old_bucket(a, ka, old_idx);         /* :795 */
        if (!added) {
            QGP_LOG_ERROR(LOG_TAG, "Could not re-add ka %s to oldBucketIdx %d",
                          ka->addr_str, old_idx);
            ka_release(ka);
        }
    }
    return CMT_OK;
}

/* :803-810 removeAddress */
static void remove_address(cmt_p2p_addrbook_t *a, const cmt_p2p_netaddr_t *addr)
{
    ka_t *ka = lookup_get(a, addr->id);

    if (ka == NULL) {
        return;
    }
    QGP_LOG_INFO(LOG_TAG, "Remove address from book %s", ka->addr_str);
    remove_from_all_buckets(a, ka);
    ka_release(ka);
}

/* :812-827 addBadPeer */
static bool add_bad_peer(cmt_p2p_addrbook_t *a, const cmt_p2p_netaddr_t *addr,
                         int64_t ban)
{
    ka_t *ka = lookup_get(a, addr->id);                    /* :814 */
    void *na;
    bool found;
    int at;

    if (ka == NULL) {
        return false;                                      /* :816-818 */
    }
    at = bad_search(a, addr->id, &found);
    if (!found) {                                          /* :820-825 */
        na = grow(a->bad, &a->cap_bad, a->n_bad, sizeof(*a->bad));
        if (na == NULL) {
            return false;
        }
        a->bad = (ka_t **)na;
        ka_ban(ka, ab_now(a), ban);
        memmove(&a->bad[at + 1], &a->bad[at],
                (size_t)(a->n_bad - at) * sizeof(*a->bad));  /* kept sorted */
        a->bad[at] = ka;
        a->n_bad++;
        ka->in_bad = true;
        QGP_LOG_INFO(LOG_TAG, "Add address to blacklist %s", ka->addr_str);
    }
    return true;
}

/* ══ addAddress (:644-700) with R-P2P-4 ═══════════════════════════════ */

/* :645-672 — the admission checks shared by the unsigned path, the signed
 * path and the load re-validation (R-P2P-38). */
static int admit_checks(const cmt_p2p_addrbook_t *a, const cmt_p2p_netaddr_t *addr,
                        const cmt_p2p_netaddr_t *src)
{
    char s[CMT_P2P_NETADDR_STR_MAX];

    if (addr == NULL || src == NULL) {
        return CMT_P2P_AB_ERR_NIL_ADDR;                    /* :645-647 */
    }
    if (cmt_p2p_netaddr_valid(addr) != CMT_P2P_ERR_NONE) {
        return CMT_P2P_AB_ERR_INVALID_ADDR;                /* :649-651 */
    }
    if (bad_index(a, addr->id) >= 0) {
        return CMT_P2P_AB_ERR_BANNED;                      /* :653-655 */
    }
    if (is_private_id(a, addr->id)) {
        return CMT_P2P_AB_ERR_PRIVATE;                     /* :657-659 */
    }
    if (is_private_id(a, src->id)) {
        return CMT_P2P_AB_ERR_PRIVATE_SRC;                 /* :661-663 */
    }
    (void)cmt_p2p_netaddr_string(addr, s, sizeof(s));
    if (is_our(a, s)) {
        return CMT_P2P_AB_ERR_SELF;                        /* :666-668 */
    }
    if (a->cfg.routability_strict && !cmt_p2p_netaddr_routable(addr)) {
        return CMT_P2P_AB_ERR_NON_ROUTABLE;                /* :670-672 */
    }
    return CMT_P2P_AB_OK;
}

static int add_address(cmt_p2p_addrbook_t *a, const cmt_p2p_netaddr_t *addr,
                       const cmt_p2p_netaddr_t *src)
{
    ka_t *ka;
    bool fresh = false;
    int bucket, rc;

    rc = admit_checks(a, addr, src);
    if (rc != CMT_P2P_AB_OK) {
        return rc;
    }
    if (is_bonded(a, addr->id)) {
        return CMT_P2P_AB_ERR_UNSIGNED_BONDED;             /* R-P2P-4 */
    }
    ka = lookup_get(a, addr->id);                          /* :674 */
    if (ka != NULL) {
        if (ka_is_old(ka) && strcmp(ka->addr.id, addr->id) == 0) {
            return CMT_P2P_AB_OK;                          /* :679-681 */
        }
        if (ka->n_buckets == CMT_P2P_AB_MAX_NEW_BUCKETS_PER_ADDRESS) {
            return CMT_P2P_AB_OK;                          /* :683-685 */
        }
        if (ab_rand(a, 2 * ka->n_buckets) != 0) {          /* :687-690 */
            return CMT_P2P_AB_OK;
        }
    } else {
        ka = ka_new(addr, src, ab_now(a));                 /* :692 */
        if (ka == NULL) {
            return CMT_FAULT;
        }
        fresh = true;
    }
    bucket = cmt_p2p_addrbook_calc_new_bucket(a, addr, src);   /* :695 */
    if (bucket < 0) {
        if (fresh) {
            ka_release(ka);
        }
        return CMT_FAULT;
    }
    rc = add_to_new_bucket(a, ka, bucket);                 /* :699 */
    if (fresh) {
        ka_release(ka);                  /* freed only if it went nowhere */
    }
    return rc;
}

/* ══ the AddrBook interface (:186-488) ════════════════════════════════ */

void cmt_p2p_addrbook_add_our_address(cmt_p2p_addrbook_t *a,
                                      const cmt_p2p_netaddr_t *addr)
{
    char s[CMT_P2P_NETADDR_STR_MAX];
    void *na;

    if (a == NULL || addr == NULL) {
        return;
    }
    (void)cmt_p2p_netaddr_string(addr, s, sizeof(s));
    QGP_LOG_INFO(LOG_TAG, "Add our address to book %s", s);
    if (is_our(a, s)) {
        return;
    }
    na = realloc(a->our, (size_t)(a->n_our + 1) * sizeof(*a->our));
    if (na == NULL) {
        return;
    }
    a->our = (char (*)[CMT_P2P_NETADDR_STR_MAX])na;
    memcpy(a->our[a->n_our++], s, sizeof(s));             /* :191 */
}

bool cmt_p2p_addrbook_our_address(const cmt_p2p_addrbook_t *a,
                                  const cmt_p2p_netaddr_t *addr)
{
    char s[CMT_P2P_NETADDR_STR_MAX];

    if (a == NULL || addr == NULL) {
        return false;
    }
    (void)cmt_p2p_netaddr_string(addr, s, sizeof(s));
    return is_our(a, s);                                   /* :199 */
}

void cmt_p2p_addrbook_add_private_ids(cmt_p2p_addrbook_t *a,
                                      const char *const *ids, int n)
{
    int i;

    if (a == NULL || ids == NULL) {
        return;
    }
    for (i = 0; i < n; i++) {                              /* :207-209 */
        void *na;
        size_t len;

        if (ids[i] == NULL || is_private_id(a, ids[i])) {
            continue;
        }
        len = strlen(ids[i]);
        if (len >= CMT_P2P_ID_CAP) {
            continue;                    /* cannot equal any ID we store */
        }
        na = realloc(a->priv, (size_t)(a->n_priv + 1) * sizeof(*a->priv));
        if (na == NULL) {
            return;
        }
        a->priv = (char (*)[CMT_P2P_ID_CAP])na;
        memcpy(a->priv[a->n_priv], ids[i], len + 1);
        a->n_priv++;
    }
}

int cmt_p2p_addrbook_add_address(cmt_p2p_addrbook_t *a,
                                 const cmt_p2p_netaddr_t *addr,
                                 const cmt_p2p_netaddr_t *src)
{
    if (a == NULL) {
        return CMT_FAULT;
    }
    return add_address(a, addr, src);                      /* :216-221 */
}

/* R-P2P-43 — queue the signature check of a record that passed every
 * other check (cmt_p2p_addrbook.h). */
static int pending_submit(cmt_p2p_addrbook_t *a, const cmt_p2p_netaddr_t *addr,
                          const cmt_p2p_netaddr_t *src, const uint8_t *rec,
                          size_t rec_len, const cmt_p2p_addr_rec_t *r,
                          const uint8_t pk[QGP_DSA87_PUBLICKEYBYTES])
{
    ab_pending_t *p;
    int i;

    for (i = 0; i < a->n_pend; i++) {
        if (strcmp(a->pend[i].id, r->id) == 0 && a->pend[i].seq >= r->seq) {
            return CMT_P2P_AB_ERR_RECORD_NOT_NEWER;     /* already in flight */
        }
    }
    if (a->n_pend >= CMT_P2P_AB_MAX_PENDING_VERIFY || rec_len > sizeof(p->rec)) {
        return CMT_P2P_AB_ERR_VERIFY_QUEUE_FULL;
    }
    if (a->pend == NULL) {
        a->pend = (ab_pending_t *)calloc(CMT_P2P_AB_MAX_PENDING_VERIFY,
                                         sizeof(*a->pend));
        if (a->pend == NULL) {
            return CMT_FAULT;
        }
    }
    p = &a->pend[a->n_pend];
    memset(p, 0, sizeof(*p));
    p->ticket = ++a->next_ticket;
    memcpy(p->rec, rec, rec_len);
    p->rec_len = rec_len;
    p->has_addr = addr != NULL;
    if (addr != NULL) {
        p->addr = *addr;
    }
    p->src = *src;
    memcpy(p->pk, pk, QGP_DSA87_PUBLICKEYBYTES);
    memcpy(p->id, r->id, sizeof(p->id));
    p->seq = r->seq;
    if (a->host.verify_addr_submit(a->host.ctx, p->ticket, p->rec,
                                   CMT_P2P_ADDR_REC_PAYLOAD_SIZE,
                                   p->rec + CMT_P2P_ADDR_REC_PAYLOAD_SIZE,
                                   p->pk) != 0) {
        return CMT_P2P_AB_ERR_VERIFY_QUEUE_FULL;        /* not kept */
    }
    a->n_pend++;
    return CMT_P2P_AB_PENDING;
}

/* R-P2P-4 (file header). `sig_known` false: the signature has not been
 * checked yet (a worker host queues it, R-P2P-43; otherwise it is checked
 * here); true: `sig_rc` is the worker's verdict over `sig_pk`. */
static int add_signed_core(cmt_p2p_addrbook_t *a, const cmt_p2p_netaddr_t *addr,
                           const cmt_p2p_netaddr_t *src, const uint8_t *rec,
                           size_t rec_len, cmt_p2p_netaddr_t *addr_out,
                           bool sig_known, int sig_rc, const uint8_t *sig_pk)
{
    cmt_p2p_addr_rec_t r;
    cmt_p2p_netaddr_t entry;
    uint8_t pk[QGP_DSA87_PUBLICKEYBYTES];
    ka_t *ka;
    int rc, bucket;

    if (cmt_p2p_addr_rec_parse(rec, rec_len, &r) != CMT_OK) {
        return CMT_P2P_AB_ERR_RECORD_MALFORMED;
    }
    entry = cmt_p2p_netaddr_new_ip_port(&r.ip, r.port);
    memcpy(entry.id, r.id, sizeof(entry.id));
    if (addr_out != NULL) {
        *addr_out = entry;
    }
    if (memcmp(r.chain_id, a->cfg.chain_id, CMT_P2P_ADDR_REC_CHAIN_LEN) != 0) {
        return CMT_P2P_AB_ERR_RECORD_CHAIN;
    }
    if (addr != NULL &&
        (strcmp(addr->id, r.id) != 0 || addr->port != r.port ||
         !cmt_p2p_ip_equal(&addr->ip, &r.ip))) {
        return CMT_P2P_AB_ERR_RECORD_MISMATCH;
    }
    rc = rec_prechecks(a, rec, rec_len, &r, pk);
    if (rc != CMT_P2P_AB_OK) {
        return rc;
    }
    if (!sig_known) {
        if (a->host.verify_addr_submit != NULL) {
            ka = lookup_get(a, r.id);
            if (ka != NULL && ka->rec != NULL && r.seq <= ka->seq) {
                return CMT_P2P_AB_ERR_RECORD_NOT_NEWER;    /* P5, before any work */
            }
            return pending_submit(a, addr, src, rec, rec_len, &r, pk);
        }
        rc = rec_sig_sync(a, rec, pk);
        if (rc != CMT_P2P_AB_OK) {
            return rc;
        }
    } else {
        if (sig_rc != 0) {
            return CMT_P2P_AB_ERR_RECORD_SIG;
        }
        if (sig_pk == NULL || memcmp(sig_pk, pk, sizeof(pk)) != 0) {
            return CMT_P2P_AB_ERR_RECORD_KEY;              /* the chain key moved */
        }
    }
    if (a->cfg.self_id[0] != '\0' && strcmp(r.id, a->cfg.self_id) == 0) {
        /* rec_prechecks pinned rec_len == CMT_P2P_ADDR_REC_SIZE. The
         * bytes are kept so the host can tell its OWN record echoed
         * back (same seq, same bytes — nothing to do) from another
         * signer's at the same seq (red-team M1). */
        if (!a->own_seen || r.seq > a->own_seq) {
            a->own_seen = true;
            a->own_seq = r.seq;
            memcpy(a->own_rec, rec, CMT_P2P_ADDR_REC_SIZE);
            a->own_rec_conflict = false;
        } else if (r.seq == a->own_seq &&
                   memcmp(a->own_rec, rec, CMT_P2P_ADDR_REC_SIZE) != 0) {
            a->own_rec_conflict = true;
        }
        return CMT_P2P_AB_ERR_SELF;
    }
    rc = admit_checks(a, &entry, src);                     /* :645-672 */
    if (rc != CMT_P2P_AB_OK) {
        return rc;
    }
    ka = lookup_get(a, r.id);
    if (ka != NULL) {
        if (ka->rec != NULL && r.seq <= ka->seq) {
            return CMT_P2P_AB_ERR_RECORD_NOT_NEWER;        /* P5: equal is not newer */
        }
        if (ka->addr.port == entry.port && cmt_p2p_ip_equal(&ka->addr.ip, &entry.ip)) {
            return ka_set_record(ka, rec, r.seq) == CMT_OK ? CMT_P2P_AB_OK : CMT_FAULT;
        }
        QGP_LOG_INFO(LOG_TAG, "newer signed record moves %s", ka->addr_str);
        remove_from_all_buckets(a, ka);                    /* replace (file header) */
        ka_release(ka);
    }
    ka = ka_new(&entry, src, ab_now(a));
    if (ka == NULL) {
        return CMT_FAULT;
    }
    if (ka_set_record(ka, rec, r.seq) != CMT_OK) {
        ka_free(ka);
        return CMT_FAULT;
    }
    bucket = cmt_p2p_addrbook_calc_new_bucket(a, &entry, src);
    if (bucket < 0) {
        ka_free(ka);
        return CMT_FAULT;
    }
    rc = add_to_new_bucket(a, ka, bucket);
    ka_release(ka);
    return rc;
}

int cmt_p2p_addrbook_add_signed(cmt_p2p_addrbook_t *a,
                                const cmt_p2p_netaddr_t *addr,
                                const cmt_p2p_netaddr_t *src,
                                const uint8_t *rec, size_t rec_len,
                                cmt_p2p_netaddr_t *addr_out)
{
    if (a == NULL || src == NULL || rec == NULL) {
        return CMT_FAULT;
    }
    return add_signed_core(a, addr, src, rec, rec_len, addr_out, false, 0, NULL);
}

/* R-P2P-43 — the worker's verdict (cmt_p2p_addrbook.h). */
int cmt_p2p_addrbook_verify_done(cmt_p2p_addrbook_t *a, uint64_t ticket,
                                 int verify_rc)
{
    ab_pending_t *p;
    int i, rc;

    if (a == NULL) {
        return CMT_FAULT;
    }
    for (i = 0; i < a->n_pend; i++) {
        if (a->pend[i].ticket == ticket) {
            break;
        }
    }
    if (i == a->n_pend) {
        return CMT_REJECT;
    }
    p = (ab_pending_t *)malloc(sizeof(*p));
    if (p == NULL) {
        return CMT_FAULT;
    }
    *p = a->pend[i];
    memmove(&a->pend[i], &a->pend[i + 1],
            (size_t)(a->n_pend - i - 1) * sizeof(*a->pend));
    a->n_pend--;
    rc = add_signed_core(a, p->has_addr ? &p->addr : NULL, &p->src, p->rec,
                         p->rec_len, NULL, true, verify_rc, p->pk);
    if (rc != CMT_P2P_AB_OK) {
        QGP_LOG_DEBUG(LOG_TAG, "queued record of %s not added: %s", p->id,
                      cmt_p2p_ab_err_str(rc));
    }
    free(p);
    return rc;
}

int cmt_p2p_addrbook_pending_verifications(const cmt_p2p_addrbook_t *a)
{
    return a != NULL ? a->n_pend : 0;
}

void cmt_p2p_addrbook_remove_address(cmt_p2p_addrbook_t *a,
                                     const cmt_p2p_netaddr_t *addr)
{
    if (a != NULL && addr != NULL) {
        remove_address(a, addr);                           /* :224-229 */
    }
}

bool cmt_p2p_addrbook_is_good(const cmt_p2p_addrbook_t *a,
                              const cmt_p2p_netaddr_t *addr)
{
    return a != NULL && addr != NULL && ka_is_old(lookup_get(a, addr->id));   /* :237 */
}

bool cmt_p2p_addrbook_is_banned(const cmt_p2p_addrbook_t *a,
                                const cmt_p2p_netaddr_t *addr)
{
    return a != NULL && addr != NULL && bad_index(a, addr->id) >= 0;          /* :243 */
}

bool cmt_p2p_addrbook_has_address(const cmt_p2p_addrbook_t *a,
                                  const cmt_p2p_netaddr_t *addr)
{
    return a != NULL && addr != NULL && lookup_get(a, addr->id) != NULL;      /* :254-255 */
}

int cmt_p2p_addrbook_size(const cmt_p2p_addrbook_t *a)
{
    return a != NULL ? a->n_new + a->n_old : 0;            /* :486-488 */
}

bool cmt_p2p_addrbook_need_more_addrs(const cmt_p2p_addrbook_t *a)
{
    return cmt_p2p_addrbook_size(a) < CMT_P2P_AB_NEED_ADDRESS_THRESHOLD;  /* :260 */
}

bool cmt_p2p_addrbook_empty(const cmt_p2p_addrbook_t *a)
{
    return cmt_p2p_addrbook_size(a) == 0;                  /* :266 */
}

/* :275-321 PickAddress */
bool cmt_p2p_addrbook_pick_address(cmt_p2p_addrbook_t *a, int bias,
                                   cmt_p2p_netaddr_t *out)
{
    double old_corr, new_corr;
    bool from_old;
    bucket_t *b = NULL;
    int tries = 0, n_buckets;

    if (a == NULL || out == NULL || cmt_p2p_addrbook_size(a) <= 0) {
        return false;                                      /* :279-285 */
    }
    if (bias > 100) {
        bias = 100;                                        /* :286-291 */
    }
    if (bias < 0) {
        bias = 0;
    }
    old_corr = sqrt((double)a->n_old) * (100.0 - (double)bias);    /* :294 */
    new_corr = sqrt((double)a->n_new) * (double)bias;              /* :295 */
    from_old = (new_corr + old_corr) * ab_float64(a) < old_corr;   /* :299 */
    if ((from_old && a->n_old == 0) || (!from_old && a->n_new == 0)) {
        return false;                                      /* :300-303 */
    }
    n_buckets = from_old ? CMT_P2P_AB_OLD_BUCKET_COUNT : CMT_P2P_AB_NEW_BUCKET_COUNT;
    while (b == NULL || b->n == 0) {                       /* :305-311 */
        int idx;

        if (tries >= 4 * n_buckets) {                      /* R-P2P-39 */
            int start = (int)ab_rand(a, n_buckets), k;

            b = NULL;
            for (k = 0; k < n_buckets; k++) {
                bucket_t *c = from_old ? &a->bold[(start + k) % n_buckets]
                                       : &a->bnew[(start + k) % n_buckets];

                if (c->n > 0) {
                    b = c;
                    break;
                }
            }
            if (b == NULL) {
                return false;
            }
            break;
        }
        idx = (int)ab_rand(a, n_buckets);
        b = from_old ? &a->bold[idx] : &a->bnew[idx];
        tries++;
    }
    {
        int ri = (int)ab_rand(a, b->n);                    /* :313-319 */

        *out = b->e[ri]->addr;
    }
    return true;
}

void cmt_p2p_addrbook_mark_good(cmt_p2p_addrbook_t *a, const char *id)
{
    ka_t *ka;

    if (a == NULL || id == NULL) {
        return;
    }
    ka = lookup_get(a, id);                                /* :329-332 */
    if (ka == NULL) {
        return;
    }
    ka_mark_good(ka, ab_now(a));                           /* :333 */
    if (ka_is_new(ka)) {                                   /* :334-338 */
        if (move_to_old(a, ka) != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "Error moving address to old");
        }
    }
}

void cmt_p2p_addrbook_mark_attempt(cmt_p2p_addrbook_t *a,
                                   const cmt_p2p_netaddr_t *addr)
{
    ka_t *ka;

    if (a == NULL || addr == NULL) {
        return;
    }
    ka = lookup_get(a, addr->id);                          /* :346-349 */
    if (ka != NULL) {
        ka_mark_attempt(ka, ab_now(a));                    /* :350 */
    }
}

void cmt_p2p_addrbook_mark_bad(cmt_p2p_addrbook_t *a,
                               const cmt_p2p_netaddr_t *addr, int64_t ban_ns)
{
    if (a == NULL || addr == NULL) {
        return;
    }
    /* A BONDED identity is never banned (red-team Z2-F11). A ban refuses
     * every address for its ID (admit_checks, :653-655) — its SIGNED
     * record too — for the whole ban time (24 h, pex_reactor.go:57), so
     * one stale unsigned entry that failed its dials, or one misbehaving
     * PEX exchange, would cut a validator off from this node for a day.
     * The misbehaving connection is still stopped by the caller (the
     * reference's StopPeerForError beside each MarkBad). No reference
     * counterpart: the reference has no bonded set (R-P2P-4). */
    if (is_bonded(a, addr->id)) {
        QGP_LOG_DEBUG(LOG_TAG, "bonded %s not banned", addr->id);
        return;
    }
    if (add_bad_peer(a, addr, ban_ns)) {                   /* :359-361 */
        remove_address(a, addr);
    }
}

int cmt_p2p_addrbook_purge_bonded_unsigned(cmt_p2p_addrbook_t *a)
{
    int i, n = 0;

    if (a == NULL || a->host.bonded_pubkey == NULL) {
        return 0;
    }
    /* Backwards: removal shifts the tail of each sorted array. */
    for (i = a->n_lookup - 1; i >= 0; i--) {
        ka_t *ka = a->lookup[i];

        if (ka->rec == NULL && is_bonded(a, ka->addr.id)) {
            QGP_LOG_INFO(LOG_TAG, "%s is bonded now: its unsigned entry %s "
                         "is dropped (only a signed record is kept)",
                         ka->addr.id, ka->addr_str);
            remove_from_all_buckets(a, ka);
            ka_release(ka);
            n++;
        }
    }
    for (i = a->n_bad - 1; i >= 0; i--) {
        ka_t *ka = a->bad[i];

        if (is_bonded(a, ka->addr.id)) {
            QGP_LOG_INFO(LOG_TAG, "%s is bonded now: its ban is lifted",
                         ka->addr.id);
            bad_delete_at(a, i);
            ka_release(ka);
            n++;
        }
    }
    return n;                  /* the saveRoutine ticker persists it */
}

/* :366-389 ReinstateBadPeers */
void cmt_p2p_addrbook_reinstate_bad_peers(cmt_p2p_addrbook_t *a)
{
    int64_t now;
    int i;

    if (a == NULL) {
        return;
    }
    now = ab_now(a);
    for (i = 0; i < a->n_bad;) {
        ka_t *ka = a->bad[i];
        int bucket;

        if (ka_is_banned(ka, now)) {                       /* :371-373 */
            i++;
            continue;
        }
        bucket = cmt_p2p_addrbook_calc_new_bucket(a, &ka->addr, &ka->src);
        if (bucket < 0) {                                  /* :375-380 */
            QGP_LOG_ERROR(LOG_TAG, "Failed to calculate new bucket (bad peer "
                          "won't be reinstantiated) %s", ka->addr_str);
            i++;
            continue;
        }
        if (add_to_new_bucket(a, ka, bucket) != CMT_P2P_AB_OK) {    /* :382-384 */
            QGP_LOG_ERROR(LOG_TAG, "Error adding peer to new bucket");
        }
        bad_delete_at(a, i);                               /* :385 */
        QGP_LOG_INFO(LOG_TAG, "Reinstated address %s", ka->addr_str);
        ka_release(ka);
    }
}

static int selection_size(int book_size)
{
    int n = CMT_P2P_AB_MIN_GET_SELECTION < book_size ? CMT_P2P_AB_MIN_GET_SELECTION
                                                     : book_size;
    int pct = book_size * CMT_P2P_AB_GET_SELECTION_PERCENT / 100;

    if (pct > n) {
        n = pct;                                           /* :406-408 MaxInt */
    }
    if (n > CMT_P2P_AB_MAX_GET_SELECTION) {
        n = CMT_P2P_AB_MAX_GET_SELECTION;                  /* :409 */
    }
    return n;
}

/* :394-430 GetSelection */
int cmt_p2p_addrbook_get_selection(cmt_p2p_addrbook_t *a, cmt_p2p_netaddr_t *out)
{
    ka_t **all;
    int size, num, i;

    if (a == NULL || out == NULL) {
        return 0;
    }
    size = cmt_p2p_addrbook_size(a);
    if (size <= 0 || a->n_lookup == 0) {
        return 0;                                          /* :398-404 */
    }
    num = selection_size(size);
    if (num > a->n_lookup) {
        num = a->n_lookup;
    }
    all = (ka_t **)malloc((size_t)a->n_lookup * sizeof(*all));  /* :413-418 */
    if (all == NULL) {
        return 0;
    }
    memcpy(all, a->lookup, (size_t)a->n_lookup * sizeof(*all));
    for (i = 0; i < num; i++) {                            /* :422-426 */
        int j = (int)ab_rand(a, a->n_lookup - i) + i;
        ka_t *t = all[i];

        all[i] = all[j];
        all[j] = t;
    }
    for (i = 0; i < num; i++) {
        out[i] = all[i]->addr;                             /* :429 */
    }
    free(all);
    return num;
}

/* :432-434 percentageOfNum — the same float64 arithmetic. */
static int percentage_of_num(int p, int n)
{
    return (int)round(((double)p / (double)100) * (double)n);
}

/* :702-738 randomPickAddresses */
static int random_pick_addresses(cmt_p2p_addrbook_t *a, uint8_t type, int num,
                                 cmt_p2p_netaddr_t *out, int have)
{
    int nb = type == CMT_P2P_AB_BUCKET_TYPE_NEW ? CMT_P2P_AB_NEW_BUCKET_COUNT
                                                : CMT_P2P_AB_OLD_BUCKET_COUNT;
    bucket_t *bs = type == CMT_P2P_AB_BUCKET_TYPE_NEW ? a->bnew : a->bold;
    ka_t **addresses;
    const char **chosen;
    int total = 0, k = 0, i, b, picked = 0;

    if (num <= 0) {
        return 0;
    }
    for (b = 0; b < nb; b++) {
        total += bs[b].n;                                  /* :713-715 */
    }
    if (total == 0) {
        return 0;
    }
    addresses = (ka_t **)malloc((size_t)total * sizeof(*addresses));
    if (addresses == NULL) {
        return 0;
    }
    for (b = 0; b < nb; b++) {                             /* :717-721 */
        for (i = 0; i < bs[b].n; i++) {
            addresses[k++] = bs[b].e[i];
        }
    }
    for (i = total - 1; i > 0; i--) {                      /* :724-726 rand.Shuffle */
        int j = (int)ab_rand(a, (int64_t)i + 1);
        ka_t *t = addresses[i];

        addresses[i] = addresses[j];
        addresses[j] = t;
    }
    /* :723 chosenSet — local to this call, keyed by Addr.String(). */
    chosen = (const char **)malloc((size_t)num * sizeof(*chosen));
    if (chosen == NULL) {
        free(addresses);
        return 0;
    }
    for (i = 0; i < total; i++) {                          /* :727-736 */
        bool seen = false;
        int c;

        for (c = 0; c < picked; c++) {
            if (strcmp(chosen[c], addresses[i]->addr_str) == 0) {
                seen = true;
                break;
            }
        }
        if (seen) {
            continue;
        }
        chosen[picked] = addresses[i]->addr_str;
        out[have + picked] = addresses[i]->addr;
        picked++;
        if (picked >= num) {
            break;
        }
    }
    free(chosen);
    free(addresses);
    return picked;
}

/* :444-474 GetSelectionWithBias */
int cmt_p2p_addrbook_get_selection_with_bias(cmt_p2p_addrbook_t *a, int bias,
                                             cmt_p2p_netaddr_t *out)
{
    int size, num, req, n;

    if (a == NULL || out == NULL) {
        return 0;
    }
    size = cmt_p2p_addrbook_size(a);
    if (size <= 0) {
        return 0;                                          /* :448-454 */
    }
    if (bias > 100) {
        bias = 100;
    }
    if (bias < 0) {
        bias = 0;
    }
    num = selection_size(size);                            /* :463-466 */
    req = percentage_of_num(bias, num);                    /* :470 */
    if (num - a->n_old > req) {
        req = num - a->n_old;
    }
    n = random_pick_addresses(a, CMT_P2P_AB_BUCKET_TYPE_NEW, req, out, 0);      /* :471 */
    n += random_pick_addresses(a, CMT_P2P_AB_BUCKET_TYPE_OLD, num - n, out, n);  /* :472 */
    return n;
}

void cmt_p2p_addrbook_save(cmt_p2p_addrbook_t *a)
{
    if (a != NULL) {
        save_to_file(a);                                   /* :493-495 */
    }
}

/* ══ R-P2P-4 accessors ════════════════════════════════════════════════ */

const uint8_t *cmt_p2p_addrbook_record(const cmt_p2p_addrbook_t *a,
                                       const char *id, uint64_t *seq)
{
    ka_t *ka = a != NULL ? lookup_get(a, id) : NULL;

    if (ka == NULL || ka->rec == NULL) {
        return NULL;
    }
    if (seq != NULL) {
        *seq = ka->seq;
    }
    return ka->rec;
}

bool cmt_p2p_addrbook_is_bonded(const cmt_p2p_addrbook_t *a, const char *id)
{
    return a != NULL && id != NULL && is_bonded(a, id);
}

bool cmt_p2p_addrbook_own_seq_seen(const cmt_p2p_addrbook_t *a, uint64_t *seq)
{
    if (a == NULL || !a->own_seen) {
        return false;
    }
    if (seq != NULL) {
        *seq = a->own_seq;
    }
    return true;
}

bool cmt_p2p_addrbook_own_seq_differs(const cmt_p2p_addrbook_t *a,
                                      const uint8_t rec[CMT_P2P_ADDR_REC_SIZE])
{
    if (a == NULL || rec == NULL || !a->own_seen) {
        return false;
    }
    return a->own_rec_conflict ||
           memcmp(a->own_rec, rec, CMT_P2P_ADDR_REC_SIZE) != 0;
}

/* ── the switch seam (R-P2P-31) ── */

static int seam_add_address(void *ctx, const cmt_p2p_netaddr_t *addr,
                            const cmt_p2p_netaddr_t *src)
{
    return cmt_p2p_addrbook_add_address((cmt_p2p_addrbook_t *)ctx, addr, src);
}

static void seam_add_private_ids(void *ctx, const char *const *ids, int n)
{
    cmt_p2p_addrbook_add_private_ids((cmt_p2p_addrbook_t *)ctx, ids, n);
}

static void seam_add_our_address(void *ctx, const cmt_p2p_netaddr_t *addr)
{
    cmt_p2p_addrbook_add_our_address((cmt_p2p_addrbook_t *)ctx, addr);
}

static void seam_mark_good(void *ctx, const char *id)
{
    cmt_p2p_addrbook_mark_good((cmt_p2p_addrbook_t *)ctx, id);
}

static void seam_remove_address(void *ctx, const cmt_p2p_netaddr_t *addr)
{
    cmt_p2p_addrbook_remove_address((cmt_p2p_addrbook_t *)ctx, addr);
}

static void seam_save(void *ctx)
{
    cmt_p2p_addrbook_save((cmt_p2p_addrbook_t *)ctx);
}

void cmt_p2p_addrbook_switch_seam(cmt_p2p_addrbook_t *a, cmt_p2p_addr_book_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->ctx = a;
    out->add_address = seam_add_address;
    out->add_private_ids = seam_add_private_ids;
    out->add_our_address = seam_add_our_address;
    out->mark_good = seam_mark_good;
    out->remove_address = seam_remove_address;
    out->save = seam_save;
}

/* ── test accessors ── */

bool cmt_p2p_addrbook_entry(const cmt_p2p_addrbook_t *a, const char *id,
                            uint8_t *bucket_type, int *buckets, int *n_buckets,
                            int32_t *attempts)
{
    ka_t *ka = a != NULL ? lookup_get(a, id) : NULL;

    if (ka == NULL) {
        return false;
    }
    if (bucket_type != NULL) {
        *bucket_type = ka->bucket_type;
    }
    if (buckets != NULL) {
        memcpy(buckets, ka->buckets, (size_t)ka->n_buckets * sizeof(int));
    }
    if (n_buckets != NULL) {
        *n_buckets = ka->n_buckets;
    }
    if (attempts != NULL) {
        *attempts = ka->attempts;
    }
    return true;
}

const char *cmt_p2p_addrbook_key(const cmt_p2p_addrbook_t *a)
{
    return a != NULL ? a->key : NULL;
}

void cmt_p2p_addrbook_counts(const cmt_p2p_addrbook_t *a, int *n_new, int *n_old)
{
    if (n_new != NULL) {
        *n_new = a != NULL ? a->n_new : 0;
    }
    if (n_old != NULL) {
        *n_old = a != NULL ? a->n_old : 0;
    }
}

/* ══ file.go — saving and loading (R-P2P-37, R-P2P-38) ════════════════ */

/* One NetAddress field, embedded (always written — the file keeps both). */
static void wf_netaddr(pb_w_t *w, uint32_t field, const cmt_p2p_netaddr_t *na)
{
    char ipb[CMT_P2P_IP_STR_MAX];
    cmt_p2p_netaddr_pb_t pb;
    uint8_t tmp[CMT_P2P_NETADDR_PROTO_MAX];
    size_t n = 0;

    if (cmt_p2p_netaddr_to_proto(na, ipb, &pb) != CMT_OK ||
        cmt_p2p_netaddr_pb_marshal(&pb, tmp, sizeof(tmp), &n) != CMT_OK) {
        w->err = CMT_REJECT;
        return;
    }
    w_raw(w, tmp, n);
    w_uvarint(w, (uint64_t)n);
    w_tag(w, field, 2);
}

/* A signed varint that is written even when zero (a repeated element). */
static void w_elem_varint(pb_w_t *w, uint32_t field, uint64_t v)
{
    w_uvarint(w, v);
    w_tag(w, field, 0);
}

#define KA_FILE_MAX (2 * (CMT_P2P_NETADDR_PROTO_MAX + 3) + \
                     CMT_P2P_AB_MAX_NEW_BUCKETS_PER_ADDRESS * 11 + \
                     5 * 11 + CMT_P2P_ADDR_REC_SIZE + 3 + 8)

/* file.go:18-42 saveToFile */
static void save_to_file(cmt_p2p_addrbook_t *a)
{
    uint8_t *buf;
    size_t cap, len = 0;
    pb_w_t w;
    int i;

    if (a->host.save == NULL) {
        return;
    }
    QGP_LOG_INFO(LOG_TAG, "Saving AddrBook to file (size %d)",
                 cmt_p2p_addrbook_size(a));
    cap = 64 + (size_t)a->n_lookup * (KA_FILE_MAX + 4);
    buf = (uint8_t *)malloc(cap);
    if (buf == NULL) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to save AddrBook to file: memory");
        return;
    }
    w_init(&w, buf, cap);
    for (i = a->n_lookup - 1; i >= 0; i--) {               /* :24-27, backward */
        const ka_t *ka = a->lookup[i];
        size_t before = w.i;
        int b;

        if (ka->rec != NULL) {
            wf_bytes(&w, 9, ka->rec, CMT_P2P_ADDR_REC_SIZE);
        }
        wf_varint(&w, 8, (uint64_t)ka->last_ban_time);
        wf_varint(&w, 7, (uint64_t)ka->last_success);
        wf_varint(&w, 6, (uint64_t)ka->last_attempt);
        wf_varint(&w, 5, ka->bucket_type);
        wf_varint(&w, 4, (uint64_t)(int64_t)ka->attempts);
        for (b = ka->n_buckets - 1; b >= 0; b--) {
            w_elem_varint(&w, 3, (uint64_t)(int64_t)ka->buckets[b]);
        }
        wf_netaddr(&w, 2, &ka->src);
        wf_netaddr(&w, 1, &ka->addr);
        wf_close_msg(&w, 2, before);
    }
    wf_bytes(&w, 1, (const uint8_t *)a->key, strlen(a->key));   /* :28-31 Key */
    if (w_finish(&w, &len) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to save AddrBook to file: encode");
        free(buf);
        return;
    }
    if (a->host.save(a->host.ctx, buf, len) != 0) {        /* :38-41 */
        QGP_LOG_ERROR(LOG_TAG, "Failed to save AddrBook to file");
    }
    free(buf);
}

typedef struct {
    cmt_p2p_netaddr_pb_t addr, src;
    bool     has_addr, has_src;
    int64_t  buckets[CMT_P2P_AB_MAX_NEW_BUCKETS_PER_ADDRESS];
    int      n_buckets;
    bool     too_many_buckets;
    int64_t  attempts;
    uint64_t bucket_type;
    int64_t  last_attempt, last_success, last_ban_time;
    const uint8_t *rec;
    size_t   rec_len;
} ka_file_t;

static int ka_file_unmarshal(const uint8_t *in, size_t len, ka_file_t *f)
{
    size_t off = 0;

    memset(f, 0, sizeof(*f));
    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;
        const uint8_t *p;
        size_t n;
        uint64_t v;

        if (r_tag(in, len, &off, &fn, &wt) != CMT_OK) {
            return CMT_REJECT;
        }
        switch (fn) {
        case 1:
        case 2:
            if (wt != 2 || r_ld(in, len, &off, &p, &n) != CMT_OK ||
                cmt_p2p_netaddr_pb_unmarshal(p, n, fn == 1 ? &f->addr : &f->src) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fn == 1) {
                f->has_addr = true;
            } else {
                f->has_src = true;
            }
            break;
        case 9:
            if (wt != 2 || r_ld(in, len, &off, &p, &n) != CMT_OK) {
                return CMT_REJECT;
            }
            f->rec = p;
            f->rec_len = n;
            break;
        case 3: case 4: case 5: case 6: case 7: case 8:
            if (wt != 0 || cmt_pb_get_uvarint(in, len, &off, &v) != CMT_OK) {
                return CMT_REJECT;
            }
            if (fn == 3) {
                if (f->n_buckets >= CMT_P2P_AB_MAX_NEW_BUCKETS_PER_ADDRESS) {
                    f->too_many_buckets = true;
                } else {
                    f->buckets[f->n_buckets++] = (int64_t)v;
                }
            } else if (fn == 4) {
                f->attempts = (int64_t)v;
            } else if (fn == 5) {
                f->bucket_type = v;
            } else if (fn == 6) {
                f->last_attempt = (int64_t)v;
            } else if (fn == 7) {
                f->last_success = (int64_t)v;
            } else {
                f->last_ban_time = (int64_t)v;
            }
            break;
        default:
            off = pre;
            if (pb_skip(in, len, &off) != CMT_OK) {
                return CMT_REJECT;
            }
        }
    }
    return CMT_OK;
}

/* One decoded entry → re-validated → placed (R-P2P-38). */
static void load_entry(cmt_p2p_addrbook_t *a, const ka_file_t *f)
{
    cmt_p2p_netaddr_t addr, src;
    uint8_t type;
    ka_t *ka;
    int i, j;

    if (!f->has_addr || !f->has_src || f->too_many_buckets ||
        cmt_p2p_netaddr_from_proto(&f->addr, &addr) != CMT_P2P_ERR_NONE ||
        cmt_p2p_netaddr_from_proto(&f->src, &src) != CMT_P2P_ERR_NONE) {
        return;
    }
    if (f->bucket_type != CMT_P2P_AB_BUCKET_TYPE_NEW &&
        f->bucket_type != CMT_P2P_AB_BUCKET_TYPE_OLD) {
        return;
    }
    type = (uint8_t)f->bucket_type;
    if (f->n_buckets < 1 ||
        (type == CMT_P2P_AB_BUCKET_TYPE_OLD && f->n_buckets != 1)) {
        return;
    }
    for (i = 0; i < f->n_buckets; i++) {
        bucket_t *b = get_bucket(a, type, (int)f->buckets[i]);

        if (f->buckets[i] < 0 || f->buckets[i] > 0xffff || b == NULL ||
            b->n >= CMT_P2P_AB_BUCKET_CAP) {
            return;
        }
        for (j = 0; j < i; j++) {
            if (f->buckets[j] == f->buckets[i]) {
                return;
            }
        }
    }
    if (f->attempts < INT32_MIN || f->attempts > INT32_MAX) {
        return;
    }
    if (admit_checks(a, &addr, &src) != CMT_P2P_AB_OK ||
        lookup_get(a, addr.id) != NULL) {
        return;
    }
    ka = ka_new(&addr, &src, f->last_attempt);
    if (ka == NULL) {
        return;
    }
    for (i = 0; i < f->n_buckets; i++) {
        if (bucket_find(get_bucket(a, type, (int)f->buckets[i]), ka->addr_str) >= 0) {
            ka_free(ka);
            return;
        }
    }
    if (is_bonded(a, addr.id)) {                           /* §2R4 P4 */
        cmt_p2p_addr_rec_t r;

        if (f->rec == NULL ||
            rec_verify(a, f->rec, f->rec_len, &r) != CMT_P2P_AB_OK ||
            strcmp(r.id, addr.id) != 0 || r.port != addr.port ||
            !cmt_p2p_ip_equal(&r.ip, &addr.ip) ||
            ka_set_record(ka, f->rec, r.seq) != CMT_OK) {
            QGP_LOG_WARN(LOG_TAG, "dropping stored entry %s: its signed record "
                         "does not verify", ka->addr_str);
            ka_free(ka);
            return;
        }
    }
    ka->attempts = (int32_t)f->attempts;
    ka->bucket_type = type;
    ka->last_attempt = f->last_attempt;
    ka->last_success = f->last_success;
    ka->last_ban_time = f->last_ban_time;
    for (i = 0; i < f->n_buckets; i++) {                   /* file.go:71-74 */
        bucket_t *b = get_bucket(a, type, (int)f->buckets[i]);

        b->e[b->n++] = ka;
        ka->buckets[ka->n_buckets++] = (int)f->buckets[i];
    }
    if (lookup_put(a, ka) != CMT_OK) {                     /* :75 */
        for (i = 0; i < ka->n_buckets; i++) {
            bucket_delete(get_bucket(a, type, ka->buckets[i]), ka->addr_str);
        }
        ka_free(ka);
        return;
    }
    if (type == CMT_P2P_AB_BUCKET_TYPE_NEW) {              /* :76-80 */
        a->n_new++;
    } else {
        a->n_old++;
    }
}

/* file.go:46-83 loadFromFile */
static int load_from_file(cmt_p2p_addrbook_t *a)
{
    uint8_t *bytes = NULL;
    size_t len = 0, off = 0;
    const uint8_t *key = NULL;
    size_t key_len = 0;
    int rc;

    if (a->host.load == NULL) {
        return CMT_OK;
    }
    rc = a->host.load(a->host.ctx, &bytes, &len);
    if (rc == 1) {
        return CMT_OK;                                     /* :47-51 */
    }
    if (rc != 0 || (bytes == NULL && len > 0)) {
        QGP_LOG_ERROR(LOG_TAG, "Error opening the address book file");
        free(bytes);
        return CMT_REJECT;                                 /* :54-57 */
    }
    /* Pass 1: the whole file must decode and carry a key (:59-64). */
    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;
        const uint8_t *p;
        size_t n;

        if (r_tag(bytes, len, &off, &fn, &wt) != CMT_OK) {
            goto corrupt;
        }
        if (fn == 1 || fn == 2) {
            if (wt != 2 || r_ld(bytes, len, &off, &p, &n) != CMT_OK) {
                goto corrupt;
            }
            if (fn == 1) {
                key = p;
                key_len = n;
            } else {
                ka_file_t f;

                if (ka_file_unmarshal(p, n, &f) != CMT_OK) {
                    goto corrupt;
                }
            }
        } else {
            off = pre;
            if (pb_skip(bytes, len, &off) != CMT_OK) {
                goto corrupt;
            }
        }
    }
    if (key == NULL || key_len != CMT_P2P_AB_KEY_LEN) {
        goto corrupt;
    }
    memcpy(a->key, key, CMT_P2P_AB_KEY_LEN);               /* :68 */
    a->key[CMT_P2P_AB_KEY_LEN] = '\0';
    /* Pass 2: every entry re-validated and placed (:70-81). */
    off = 0;
    while (off < len) {
        size_t pre = off;
        int32_t fn;
        uint32_t wt;
        const uint8_t *p;
        size_t n;

        (void)r_tag(bytes, len, &off, &fn, &wt);
        if (fn == 2 && r_ld(bytes, len, &off, &p, &n) == CMT_OK) {
            ka_file_t f;

            if (ka_file_unmarshal(p, n, &f) == CMT_OK) {
                load_entry(a, &f);
            }
        } else {
            off = pre;
            if (pb_skip(bytes, len, &off) != CMT_OK) {
                break;
            }
        }
    }
    free(bytes);
    return CMT_OK;

corrupt:
    QGP_LOG_ERROR(LOG_TAG, "Error reading the address book file");
    free(bytes);
    return CMT_REJECT;                                     /* :62-64 */
}
