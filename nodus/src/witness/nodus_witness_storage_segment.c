/**
 * @file nodus_witness_storage_segment.c
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2b-2 —
 *        the segment file. Layout, the verification of every piece, the
 *        atomic publish, the resume rule and the determinism statement:
 *        nodus_witness_storage_segment.h.
 *
 * Nothing here reads a clock, draws randomness or writes the database:
 * the ledger is READ (v2_blocks.block_id), the cmt state store is READ
 * (validators at k·17280, for the terminal commit's signatures), and the
 * only writes are this node's own files in its segment directory.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "witness/nodus_witness_storage_segment.h"

#include "dnac/cmt_merkle.h"
#include "dnac/cmt_pb.h"
#include "dnac/cmt_validation.h"

#include "crypto/hash/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "W_STSEG"

#define SEG_P  ((uint64_t)NODUS_SEG_COUNT)

/* The I/O scratch: the widest single thing read or written at once. */
#define SEG_IO_CAP  ((size_t)NODUS_SEG_COMMIT_MAX)

_Static_assert(NODUS_SEG_COMMIT_MAX >= NODUS_SEG_PART_PROTO_MAX &&
               NODUS_SEG_COMMIT_MAX >= NODUS_SEG_HEADER_MAX + 16u,
               "the I/O scratch holds every record piece");
_Static_assert(sizeof(NODUS_SEG_FILE_TAG) - 1 <= NODUS_SEG_TAG_LEN &&
               sizeof(NODUS_SEG_INDEX_TAG) - 1 <= NODUS_SEG_TAG_LEN &&
               sizeof(NODUS_SEG_DONE_TAG) - 1 <= NODUS_SEG_TAG_LEN,
               "the file tags fit their 16 bytes");

/* ── byte helpers ────────────────────────────────────────────────────── */

static void put64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}
static uint32_t get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void tag16(const char *tag, uint8_t out[NODUS_SEG_TAG_LEN]) {
    memset(out, 0, NODUS_SEG_TAG_LEN);
    memcpy(out, tag, strlen(tag));
}

/* ── file helpers ────────────────────────────────────────────────────── */

/* @return 0 all written / -1 */
static int pwrite_all(int fd, const uint8_t *p, size_t n, uint64_t off) {
    while (n > 0) {
        ssize_t w = pwrite(fd, p, n, (off_t)off);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) return -1;
        p += w;
        n -= (size_t)w;
        off += (uint64_t)w;
    }
    return 0;
}

/* @return 0 all read / 1 end of file first / -1 */
static int pread_all(int fd, uint8_t *p, size_t n, uint64_t off) {
    while (n > 0) {
        ssize_t r = pread(fd, p, n, (off_t)off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return 1;
        p += r;
        n -= (size_t)r;
        off += (uint64_t)r;
    }
    return 0;
}

static int fsync_dir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    return rc == 0 ? 0 : -1;
}

/* Write `path` with exactly `len` bytes and fsync it. @return 0 / -1 */
static int write_file_sync(const char *path, const uint8_t *p, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    int ok = pwrite_all(fd, p, len, 0) == 0 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    return ok ? 0 : -1;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static int unlink_quiet(const char *path) {
    if (unlink(path) == 0 || errno == ENOENT) return 0;
    QGP_LOG_WARN(LOG_TAG, "unlink %s: %s", path, strerror(errno));
    return -1;
}

/* ══════════════════════════════════════════════════════════════════════
 * Names
 * ════════════════════════════════════════════════════════════════════ */

static const char *const SEG_SUFFIX[6] = {
    ".dat.tmp", ".dat", ".idx.tmp", ".idx", ".ok.tmp", ".ok"
};

const char *nodus_seg_v_str(nodus_seg_v_t v) {
    static const char *const names[] = {
        "ok", "order", "bounds", "no-ledger-row", "header-decode",
        "header-hash", "header-height", "block-id", "part-total",
        "part-decode", "part-index", "proof-total", "part-basic", "proof",
        "commit-decode", "commit-height", "commit-block-id", "commit-hash",
        "commit-valset", "commit-sigs", "io", "fault"
    };
    if ((unsigned)v >= sizeof(names) / sizeof(names[0])) return "?";
    return names[v];
}

int nodus_seg_path(const char *dir, uint64_t k, nodus_seg_file_t which,
                   char *out, size_t cap) {
    if (!dir || !out || k == 0 || (unsigned)which > NODUS_SEG_F_OK)
        return -1;
    int n = snprintf(out, cap, "%s/seg-%" PRIu64 "%s", dir, k,
                     SEG_SUFFIX[which]);
    return (n < 0 || (size_t)n >= cap) ? -1 : 0;
}

int nodus_seg_name_parse(const char *name, uint64_t *k_out) {
    if (!name || !k_out || strncmp(name, "seg-", 4) != 0) return -1;
    const char *p = name + 4;
    uint64_t k = 0;
    size_t nd = 0;
    while (*p >= '0' && *p <= '9') {
        if (k > (UINT64_MAX - 9u) / 10u) return -1;
        k = k * 10u + (uint64_t)(*p - '0');
        p++;
        nd++;
    }
    if (nd == 0 || nd > 19 || k == 0 || name[4] == '0') return -1;
    for (size_t i = 0; i < 6; i++) {
        if (strcmp(p, SEG_SUFFIX[i]) == 0) {
            *k_out = k;
            return 0;
        }
    }
    return -1;
}

int nodus_seg_dir_ensure(const char *dir) {
    struct stat st;
    if (!dir || !dir[0]) return -1;
    if (stat(dir, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        QGP_LOG_ERROR(LOG_TAG, "segment directory %s: %s", dir,
                      strerror(errno));
        return -1;
    }
    return 0;
}

uint64_t nodus_seg_of_height(uint64_t h) {
    return h == 0 ? 0 : (h - 1u) / SEG_P + 1u;
}

/* ══════════════════════════════════════════════════════════════════════
 * The ledger
 * ════════════════════════════════════════════════════════════════════ */

/* v2_blocks.block_id at h. @return 0 / 1 absent or not 64 bytes / -1 */
static int ledger_hash(sqlite3 *db, uint64_t h, uint8_t out[64]) {
    sqlite3_stmt *st = NULL;
    if (!db || h == 0 || h > (uint64_t)INT64_MAX) return -1;
    if (sqlite3_prepare_v2(db,
            "SELECT block_id FROM v2_blocks WHERE global_height = ?1",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_int64(st, 1, (sqlite3_int64)h);
    int ret = 1;
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        if (sqlite3_column_type(st, 0) == SQLITE_BLOB &&
            sqlite3_column_bytes(st, 0) == 64 &&
            sqlite3_column_blob(st, 0) != NULL) {
            memcpy(out, sqlite3_column_blob(st, 0), 64);
            ret = 0;
        }
    } else if (rc != SQLITE_DONE) {
        ret = -1;
    }
    sqlite3_finalize(st);
    return ret;
}

/* ══════════════════════════════════════════════════════════════════════
 * The build
 * ════════════════════════════════════════════════════════════════════ */

struct nodus_seg_build {
    char      dir[NODUS_SEG_PATH_MAX];
    uint64_t  k, first, last;           /* last = k·17280                */
    sqlite3  *ledger;
    int       fd;                       /* .dat.tmp                      */
    uint64_t  size;                     /* verified bytes = write offset  */

    bool      scanning;                 /* the resume scan is not over    */
    uint64_t  h;                        /* first … last; last+1 = commit  */
    bool      have_hdr;                 /* header(h+1) of h held          */
    uint32_t  total;                    /* its part count                 */
    uint32_t  next_part;                /* parts of h written             */
    uint64_t  rec_off;                  /* where h's record starts        */
    uint8_t   psh_hash[64];             /* block h's part-set root        */
    uint8_t   hdr[NODUS_SEG_HEADER_MAX];/* header(h+1) proto              */
    size_t    hdr_len;

    uint8_t   vals_hash[64];            /* header(k·P).validators_hash    */
    size_t    vals_hash_len;
    bool      have_term;                /* header(k·P+1) held             */
    cmt_pb_header_t *term;              /* header(k·P+1), decoded         */

    bool      commit_done;
    uint64_t  commit_off;
    uint32_t  commit_len;
    uint8_t   flags;

    uint8_t  *idx;                      /* NODUS_SEG_INDEX_LEN            */
    /* scratch */
    cmt_pb_header_t *hdec;
    cmt_part_t      *part;
    uint8_t         *arena;             /* CMT_BLOCK_PART_SIZE_BYTES      */
    uint8_t         *io;                /* SEG_IO_CAP                     */
};

uint64_t nodus_seg_build_k(const nodus_seg_build_t *b) {
    return b ? b->k : 0;
}

static void build_close(nodus_seg_build_t *b) {
    if (!b) return;
    if (b->fd >= 0) close(b->fd);
    free(b->io);
    free(b->arena);
    free(b->part);
    free(b->hdec);
    free(b->term);
    free(b->idx);
    free(b);
}

void nodus_seg_build_free(nodus_seg_build_t *b) {
    build_close(b);
}

void nodus_seg_build_discard(nodus_seg_build_t *b) {
    if (!b) return;
    char p[NODUS_SEG_PATH_MAX];
    if (nodus_seg_path(b->dir, b->k, NODUS_SEG_F_DAT_TMP, p, sizeof(p)) == 0)
        (void)unlink_quiet(p);
    if (nodus_seg_path(b->dir, b->k, NODUS_SEG_F_IDX_TMP, p, sizeof(p)) == 0)
        (void)unlink_quiet(p);
    if (nodus_seg_path(b->dir, b->k, NODUS_SEG_F_OK_TMP, p, sizeof(p)) == 0)
        (void)unlink_quiet(p);
    build_close(b);
}

/* The data file header for k. */
static void data_hdr(uint64_t k, uint8_t out[NODUS_SEG_DATA_HDR_LEN]) {
    tag16(NODUS_SEG_FILE_TAG, out);
    put64(out + 16, k);
    put32(out + 24, NODUS_SEG_COUNT);
}

int nodus_seg_build_open(const char *dir, uint64_t k, sqlite3 *ledger,
                         nodus_seg_build_t **out) {
    if (!out) return -1;
    *out = NULL;
    if (!dir || !ledger || k == 0 ||
        k > ((uint64_t)INT64_MAX - 1u) / SEG_P - 1u ||
        strlen(dir) >= NODUS_SEG_PATH_MAX - 40u)
        return -1;
    if (nodus_seg_dir_ensure(dir) != 0) return -1;
    /* a HELD segment is never reopened: its marker would be dropped */
    if (nodus_seg_held(dir, k) != 0) return -1;

    char dat[NODUS_SEG_PATH_MAX], tmp[NODUS_SEG_PATH_MAX];
    char p[NODUS_SEG_PATH_MAX];
    if (nodus_seg_path(dir, k, NODUS_SEG_F_DAT, dat, sizeof(dat)) != 0 ||
        nodus_seg_path(dir, k, NODUS_SEG_F_DAT_TMP, tmp, sizeof(tmp)) != 0)
        return -1;

    /* a marker that is not valid makes nothing held: drop it, and give a
     * published-but-unmarked data file back to the resume scan */
    if (nodus_seg_path(dir, k, NODUS_SEG_F_OK, p, sizeof(p)) != 0 ||
        unlink_quiet(p) != 0)
        return -1;
    if (nodus_seg_path(dir, k, NODUS_SEG_F_OK_TMP, p, sizeof(p)) != 0 ||
        unlink_quiet(p) != 0)
        return -1;
    if (nodus_seg_path(dir, k, NODUS_SEG_F_IDX, p, sizeof(p)) != 0 ||
        unlink_quiet(p) != 0)
        return -1;
    if (nodus_seg_path(dir, k, NODUS_SEG_F_IDX_TMP, p, sizeof(p)) != 0 ||
        unlink_quiet(p) != 0)
        return -1;
    if (file_exists(dat)) {
        if (file_exists(tmp)) {
            if (unlink_quiet(dat) != 0) return -1;
        } else if (rename(dat, tmp) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": %s → %s: %s", k,
                          dat, tmp, strerror(errno));
            return -1;
        }
        QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": data file without a "
                     "valid marker — re-verified by the resume scan", k);
    }

    nodus_seg_build_t *b = calloc(1, sizeof(*b));
    if (!b) return -1;
    b->fd = -1;
    memcpy(b->dir, dir, strlen(dir) + 1);
    b->k = k;
    b->first = (k - 1u) * SEG_P + 1u;
    b->last = k * SEG_P;
    b->ledger = ledger;
    b->h = b->first;
    b->idx = calloc(1, NODUS_SEG_INDEX_LEN);
    b->hdec = malloc(sizeof(*b->hdec));
    b->term = malloc(sizeof(*b->term));
    b->part = malloc(sizeof(*b->part));
    b->arena = malloc(CMT_BLOCK_PART_SIZE_BYTES);
    b->io = malloc(SEG_IO_CAP);
    if (!b->idx || !b->hdec || !b->term || !b->part || !b->arena || !b->io)
        goto fail;

    b->fd = open(tmp, O_RDWR | O_CREAT, 0600);
    if (b->fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": open %s: %s", k, tmp,
                      strerror(errno));
        goto fail;
    }
    struct stat st;
    if (fstat(b->fd, &st) != 0) goto fail;

    uint8_t want[NODUS_SEG_DATA_HDR_LEN], have[NODUS_SEG_DATA_HDR_LEN];
    data_hdr(k, want);
    int fresh = 1;
    if ((uint64_t)st.st_size >= NODUS_SEG_DATA_HDR_LEN &&
        pread_all(b->fd, have, sizeof(have), 0) == 0 &&
        memcmp(have, want, sizeof(want)) == 0)
        fresh = 0;
    if (fresh) {
        if (ftruncate(b->fd, 0) != 0 ||
            pwrite_all(b->fd, want, sizeof(want), 0) != 0)
            goto fail;
        b->scanning = false;
    } else {
        b->scanning = (uint64_t)st.st_size > NODUS_SEG_DATA_HDR_LEN;
        if (b->scanning)
            QGP_LOG_INFO(LOG_TAG, "segment %" PRIu64 ": resuming a partial "
                         "file of %lld bytes (every record re-verified)", k,
                         (long long)st.st_size);
    }
    b->size = NODUS_SEG_DATA_HDR_LEN;
    *out = b;
    return 0;
fail:
    build_close(b);
    return -1;
}

/* ── the checks (no write) ───────────────────────────────────────────── */

/* header(h+1) for the height the build is on. On OK the build holds it. */
static nodus_seg_v_t check_header(nodus_seg_build_t *b, uint64_t h,
                                  const uint8_t *hdr, size_t len) {
    uint8_t hh[64], hh1[64], got[CMT_TMHASH_SIZE];
    if (len == 0 || len > NODUS_SEG_HEADER_MAX) return NODUS_SEG_V_BOUNDS;
    int r0 = ledger_hash(b->ledger, h, hh);
    int r1 = ledger_hash(b->ledger, h + 1u, hh1);
    if (r0 < 0 || r1 < 0) return NODUS_SEG_V_FAULT;
    if (r0 != 0 || r1 != 0) return NODUS_SEG_V_NO_LEDGER;

    cmt_pb_header_init(b->hdec);
    if (cmt_pb_header_unmarshal(hdr, len, b->hdec) != CMT_OK)
        return NODUS_SEG_V_HEADER_DECODE;
    int rc = cmt_header_hash(b->hdec, got);
    if (rc == CMT_FAULT) return NODUS_SEG_V_FAULT;
    if (rc != CMT_OK || memcmp(got, hh1, 64) != 0)
        return NODUS_SEG_V_HEADER_HASH;
    if (b->hdec->height != (int64_t)(h + 1u)) return NODUS_SEG_V_HEADER_HEIGHT;
    const cmt_pb_block_id_t *bid = &b->hdec->last_block_id;
    if (bid->hash_len != 64 || memcmp(bid->hash, hh, 64) != 0)
        return NODUS_SEG_V_BLOCK_ID;
    if (bid->part_set_header.total == 0 ||
        bid->part_set_header.total > CMT_PART_SET_MAX_PARTS ||
        bid->part_set_header.hash_len != CMT_TMHASH_SIZE)
        return NODUS_SEG_V_PART_TOTAL;

    b->total = bid->part_set_header.total;
    memcpy(b->psh_hash, bid->part_set_header.hash, 64);
    memcpy(b->hdr, hdr, len);
    b->hdr_len = len;
    b->have_hdr = true;
    b->next_part = 0;
    if (h + 1u == b->last) {            /* header(k·P): its validators   */
        if (b->hdec->validators_hash_len > sizeof(b->vals_hash))
            return NODUS_SEG_V_FAULT;
        memcpy(b->vals_hash, b->hdec->validators_hash,
               b->hdec->validators_hash_len);
        b->vals_hash_len = b->hdec->validators_hash_len;
    }
    if (h == b->last) {                 /* header(k·P+1): the commit's    */
        memcpy(b->term, b->hdec, sizeof(*b->term));
        b->have_term = true;
    }
    return NODUS_SEG_V_OK;
}

/* Part `i` (a decoded cmt_pb_part in b->part) against the held header. */
static nodus_seg_v_t check_part_decoded(nodus_seg_build_t *b, uint32_t i) {
    cmt_part_t *pt = b->part;
    if (pt->index != i || pt->proof.index != (int64_t)i)
        return NODUS_SEG_V_PART_INDEX;
    if (pt->proof.total != (int64_t)b->total) return NODUS_SEG_V_PROOF_TOTAL;
    int rc = cmt_part_validate_basic(pt);
    if (rc == CMT_FAULT) return NODUS_SEG_V_FAULT;
    if (rc != CMT_OK) return NODUS_SEG_V_PART_BASIC;
    rc = cmt_proof_verify(&pt->proof, b->psh_hash, pt->bytes.data,
                          pt->bytes.len);
    if (rc == CMT_FAULT) return NODUS_SEG_V_FAULT;
    if (rc != CMT_OK) return NODUS_SEG_V_PROOF;
    return NODUS_SEG_V_OK;
}

static nodus_seg_v_t check_part_proto(nodus_seg_build_t *b, uint32_t i,
                                      const uint8_t *proto, size_t len) {
    if (len == 0 || len > NODUS_SEG_PART_PROTO_MAX) return NODUS_SEG_V_BOUNDS;
    cmt_pb_arena_t ar = { b->arena, CMT_BLOCK_PART_SIZE_BYTES, 0 };
    if (cmt_pb_part_unmarshal(proto, len, b->part, &ar) != CMT_OK)
        return NODUS_SEG_V_PART_DECODE;
    return check_part_decoded(b, i);
}

/* The terminal commit; on OK *flags gets NODUS_SEG_FLAG_SIGS when the
 * signatures were verified. */
static nodus_seg_v_t check_commit(nodus_seg_build_t *b, const uint8_t *cb,
                                  size_t len, nodus_cmt_store_t *state,
                                  uint8_t *flags) {
    *flags = 0;
    if (!b->have_term) return NODUS_SEG_V_ORDER;
    if (len == 0 || len > NODUS_SEG_COMMIT_MAX) return NODUS_SEG_V_BOUNDS;

    nodus_seg_v_t ret = NODUS_SEG_V_FAULT;
    cmt_pb_commit_t  *pb = calloc(1, sizeof(*pb));
    cmt_commit_t     *c = calloc(1, sizeof(*c));
    cmt_pb_commit_sig_t *pbs = calloc(CMT_VALSET_MAX, sizeof(*pbs));
    cmt_commit_sig_t    *sigs = calloc(CMT_VALSET_MAX, sizeof(*sigs));
    cmt_validator_t     *vals = NULL;
    uint8_t             *scratch = NULL;
    cmt_merkle_item_t   *items = NULL;
    if (!pb || !c || !pbs || !sigs) goto done;

    pb->signatures = pbs;
    pb->signatures_cap = CMT_VALSET_MAX;
    if (cmt_pb_commit_unmarshal(cb, len, pb) != CMT_OK ||
        cmt_commit_from_proto(pb, sigs, CMT_VALSET_MAX, c) != CMT_OK) {
        ret = NODUS_SEG_V_COMMIT_DECODE;
        goto done;
    }
    if (c->height != (int64_t)b->last) {
        ret = NODUS_SEG_V_COMMIT_HEIGHT;
        goto done;
    }
    {
        const cmt_pb_block_id_t *x = &c->block_id;
        const cmt_pb_block_id_t *y = &b->term->last_block_id;
        if (x->hash_len != y->hash_len ||
            memcmp(x->hash, y->hash, x->hash_len) != 0 ||
            x->part_set_header.total != y->part_set_header.total ||
            x->part_set_header.hash_len != y->part_set_header.hash_len ||
            memcmp(x->part_set_header.hash, y->part_set_header.hash,
                   x->part_set_header.hash_len) != 0) {
            ret = NODUS_SEG_V_COMMIT_BLOCK_ID;
            goto done;
        }
    }
    {
        uint8_t ch[CMT_TMHASH_SIZE];
        int rc = cmt_commit_hash(c, ch);
        if (rc == CMT_FAULT) goto done;
        if (rc != CMT_OK || b->term->last_commit_hash_len != CMT_TMHASH_SIZE ||
            memcmp(ch, b->term->last_commit_hash, CMT_TMHASH_SIZE) != 0) {
            ret = NODUS_SEG_V_COMMIT_HASH;
            goto done;
        }
    }

    /* the signatures, when this node still holds validators(k·P) */
    if (state) {
        cmt_validator_set_t vs;
        vals = calloc(CMT_VALSET_MAX, sizeof(*vals));
        if (!vals || cmt_validator_set_init(&vs, vals, CMT_VALSET_MAX)
                         != CMT_OK)
            goto done;
        int rc = nodus_cmt_ss_load_validators(state, (int64_t)b->last, &vs);
        if (rc == CMT_FAULT) goto done;
        if (rc == CMT_OK) {
            uint8_t vh[CMT_TMHASH_SIZE];
            size_t n = vs.validators_len ? vs.validators_len : 1;
            scratch = malloc(n * CMT_VALIDATOR_BYTES_MAX);
            items = calloc(n, sizeof(*items));
            if (!scratch || !items) goto done;
            rc = cmt_validator_set_hash(&vs, scratch,
                                        n * CMT_VALIDATOR_BYTES_MAX, items, n,
                                        vh);
            if (rc == CMT_FAULT) goto done;
            if (rc != CMT_OK || b->vals_hash_len != CMT_TMHASH_SIZE ||
                memcmp(vh, b->vals_hash, CMT_TMHASH_SIZE) != 0) {
                QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": this node's "
                              "validators(%" PRIu64 ") do not hash to "
                              "header(%" PRIu64 ").validators_hash", b->k,
                              b->last, b->last);
                ret = NODUS_SEG_V_COMMIT_VALSET;
                goto done;
            }
            cmt_vs_error_t err;
            memset(&err, 0, sizeof(err));
            rc = cmt_verify_commit(b->term->chain_id, b->term->chain_id_len,
                                   &vs, &b->term->last_block_id,
                                   (int64_t)b->last, c, &err);
            if (rc == CMT_FAULT) goto done;
            if (rc != CMT_OK) {
                ret = NODUS_SEG_V_COMMIT_SIGS;
                goto done;
            }
            *flags = NODUS_SEG_FLAG_SIGS;
        }
    }
    if (!(*flags & NODUS_SEG_FLAG_SIGS))
        QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": terminal commit bound "
                     "by its hash only — validators(%" PRIu64 ") are not in "
                     "this node's state store, signatures NOT verified",
                     b->k, b->last);
    ret = NODUS_SEG_V_OK;
done:
    free(items);
    free(scratch);
    free(vals);
    free(sigs);
    free(pbs);
    free(c);
    free(pb);
    return ret;
}

/* A height record is complete: index it and move on. */
static void height_done(nodus_seg_build_t *b) {
    uint8_t *e = b->idx + 28u + (b->h - b->first) * NODUS_SEG_INDEX_ENTRY_LEN;
    put64(e, b->rec_off);
    put32(e + 8, b->total);
    b->h++;
    b->have_hdr = false;
    b->next_part = 0;
}

/* ── the resume scan ─────────────────────────────────────────────────── */

static void scan_cut(nodus_seg_build_t *b, uint64_t at, const char *why) {
    QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": partial file cut at byte "
                 "%" PRIu64 " (height %" PRIu64 ": %s)", b->k, at, b->h, why);
    if (ftruncate(b->fd, (off_t)at) != 0)
        QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": ftruncate: %s", b->k,
                      strerror(errno));
    b->size = at;
    b->have_hdr = false;
    b->next_part = 0;
    b->scanning = false;
}

int nodus_seg_build_resume_step(nodus_seg_build_t *b, uint32_t max_heights) {
    if (!b) return -1;
    if (!b->scanning) return 1;
    for (uint32_t n = 0; n < max_heights; n++) {
        if (b->h > b->last) {
            /* the commit record (if any) is NOT resumed: it is checked
             * against this node's state store, which the scan does not
             * hold — cut and re-added by the source */
            struct stat st;
            if (fstat(b->fd, &st) == 0 && (uint64_t)st.st_size > b->size)
                scan_cut(b, b->size, "terminal commit re-added");
            b->scanning = false;
            return 1;
        }
        const uint64_t at = b->size;
        uint64_t off = at;
        uint8_t pre[12];
        int r = pread_all(b->fd, pre, sizeof(pre), off);
        if (r < 0) return -1;
        if (r > 0) { scan_cut(b, at, "end of the partial file"); return 1; }
        if (get64(pre) != b->h) { scan_cut(b, at, "height"); return 1; }
        uint32_t hl = get32(pre + 8);
        off += 12;
        if (hl == 0 || hl > NODUS_SEG_HEADER_MAX) {
            scan_cut(b, at, "header length");
            return 1;
        }
        r = pread_all(b->fd, b->io, hl, off);
        if (r < 0) return -1;
        if (r > 0) { scan_cut(b, at, "short header"); return 1; }
        off += hl;
        uint8_t hdr_copy[NODUS_SEG_HEADER_MAX];
        memcpy(hdr_copy, b->io, hl);
        nodus_seg_v_t v = check_header(b, b->h, hdr_copy, hl);
        if (v == NODUS_SEG_V_FAULT || v == NODUS_SEG_V_NO_LEDGER) {
            b->have_hdr = false;
            return -1;                  /* the node, not the file */
        }
        if (v != NODUS_SEG_V_OK) {
            scan_cut(b, at, nodus_seg_v_str(v));
            return 1;
        }
        uint8_t np[4];
        r = pread_all(b->fd, np, 4, off);
        if (r < 0) return -1;
        if (r > 0 || get32(np) != b->total) {
            scan_cut(b, at, "part count");
            return 1;
        }
        off += 4;
        for (uint32_t i = 0; i < b->total; i++) {
            uint8_t pl[4];
            r = pread_all(b->fd, pl, 4, off);
            if (r < 0) return -1;
            uint32_t plen = r == 0 ? get32(pl) : 0;
            if (r > 0 || plen == 0 || plen > NODUS_SEG_PART_PROTO_MAX) {
                scan_cut(b, at, "part length");
                return 1;
            }
            off += 4;
            r = pread_all(b->fd, b->io, plen, off);
            if (r < 0) return -1;
            if (r > 0) { scan_cut(b, at, "short part"); return 1; }
            off += plen;
            v = check_part_proto(b, i, b->io, plen);
            if (v == NODUS_SEG_V_FAULT) return -1;
            if (v != NODUS_SEG_V_OK) {
                scan_cut(b, at, nodus_seg_v_str(v));
                return 1;
            }
        }
        b->rec_off = at;
        b->size = off;
        height_done(b);
    }
    return 0;
}

/* ── adding pieces ───────────────────────────────────────────────────── */

int nodus_seg_build_next(const nodus_seg_build_t *b, uint64_t *h_out,
                         uint32_t *part_out, bool *header_needed) {
    if (!b || !h_out || !part_out || !header_needed || b->scanning)
        return -1;
    if (b->h <= b->last) {
        *h_out = b->h;
        *part_out = b->have_hdr ? b->next_part : 0;
        *header_needed = !b->have_hdr;
        return 0;
    }
    if (!b->commit_done) {
        *h_out = b->last;
        *part_out = NODUS_SEG_PART_COMMIT;
        *header_needed = !b->have_term;
        return 0;
    }
    return 1;
}

int nodus_seg_build_cur_header(const nodus_seg_build_t *b,
                               const uint8_t **hdr, size_t *len) {
    if (!b || !hdr || !len || !b->have_hdr) return -1;
    *hdr = b->hdr;
    *len = b->hdr_len;
    return 0;
}

nodus_seg_v_t nodus_seg_build_put_header(nodus_seg_build_t *b, uint64_t h,
                                         const uint8_t *hdr, size_t len) {
    if (!b || !hdr) return NODUS_SEG_V_FAULT;
    if (b->scanning || h != b->h || h > b->last || b->have_hdr)
        return NODUS_SEG_V_ORDER;
    nodus_seg_v_t v = check_header(b, h, hdr, len);
    if (v != NODUS_SEG_V_OK) {
        b->have_hdr = false;
        return v;
    }
    /* h u64 ‖ hdr_len u32 ‖ header ‖ n_parts u32 */
    uint8_t *w = b->io;
    put64(w, h);
    put32(w + 8, (uint32_t)len);
    memcpy(w + 12, hdr, len);
    put32(w + 12 + len, b->total);
    if (pwrite_all(b->fd, w, 16 + len, b->size) != 0) {
        b->have_hdr = false;
        return NODUS_SEG_V_IO;
    }
    b->rec_off = b->size;
    b->size += 16 + len;
    return NODUS_SEG_V_OK;
}

/* Write the verified part proto in b->io[4 ..) of `len` bytes. */
static nodus_seg_v_t write_part(nodus_seg_build_t *b, size_t len) {
    put32(b->io, (uint32_t)len);
    if (pwrite_all(b->fd, b->io, 4 + len, b->size) != 0)
        return NODUS_SEG_V_IO;
    b->size += 4 + len;
    b->next_part++;
    if (b->next_part == b->total) height_done(b);
    return NODUS_SEG_V_OK;
}

nodus_seg_v_t nodus_seg_build_put_part_proto(nodus_seg_build_t *b,
                                             uint64_t h, uint32_t i,
                                             const uint8_t *proto,
                                             size_t len) {
    if (!b || !proto) return NODUS_SEG_V_FAULT;
    if (b->scanning || !b->have_hdr || h != b->h || i != b->next_part)
        return NODUS_SEG_V_ORDER;
    nodus_seg_v_t v = check_part_proto(b, i, proto, len);
    if (v != NODUS_SEG_V_OK) return v;
    memmove(b->io + 4, proto, len);
    return write_part(b, len);
}

nodus_seg_v_t nodus_seg_build_put_part(nodus_seg_build_t *b, uint64_t h,
                                       uint32_t i,
                                       const uint8_t *part, size_t part_len,
                                       const uint8_t *proof,
                                       size_t proof_len) {
    if (!b || (!part && part_len) || !proof) return NODUS_SEG_V_FAULT;
    if (b->scanning || !b->have_hdr || h != b->h || i != b->next_part)
        return NODUS_SEG_V_ORDER;
    if (part_len > CMT_BLOCK_PART_SIZE_BYTES || proof_len == 0 ||
        proof_len > NODUS_STPROBE_PROOF_MAX)
        return NODUS_SEG_V_BOUNDS;
    cmt_part_t *pt = b->part;
    memset(pt, 0, sizeof(*pt));
    cmt_pb_proof_init(&pt->proof);
    if (cmt_pb_proof_unmarshal(proof, proof_len, &pt->proof) != CMT_OK ||
        cmt_proof_validate_basic(&pt->proof) != CMT_OK)
        return NODUS_SEG_V_PART_DECODE;
    pt->index = i;
    if (part_len) memcpy(b->arena, part, part_len);
    pt->bytes.data = b->arena;
    pt->bytes.len = part_len;
    nodus_seg_v_t v = check_part_decoded(b, i);
    if (v != NODUS_SEG_V_OK) return v;
    size_t n = 0;
    if (cmt_pb_part_marshal(pt, b->io + 4, SEG_IO_CAP - 4, &n) != CMT_OK ||
        n == 0 || n > NODUS_SEG_PART_PROTO_MAX)
        return NODUS_SEG_V_FAULT;
    return write_part(b, n);
}

nodus_seg_v_t nodus_seg_build_put_commit(nodus_seg_build_t *b,
                                         const uint8_t *commit, size_t len,
                                         nodus_cmt_store_t *state) {
    if (!b || !commit) return NODUS_SEG_V_FAULT;
    if (b->scanning || b->h != b->last + 1u || b->commit_done)
        return NODUS_SEG_V_ORDER;
    uint8_t flags = 0;
    nodus_seg_v_t v = check_commit(b, commit, len, state, &flags);
    if (v != NODUS_SEG_V_OK) return v;
    uint8_t pre[4];
    put32(pre, (uint32_t)len);
    if (pwrite_all(b->fd, pre, 4, b->size) != 0 ||
        pwrite_all(b->fd, commit, len, b->size + 4u) != 0)
        return NODUS_SEG_V_IO;
    b->commit_off = b->size + 4u;
    b->commit_len = (uint32_t)len;
    b->size += 4u + len;
    b->flags = flags;
    b->commit_done = true;
    return NODUS_SEG_V_OK;
}

int nodus_seg_build_finish(nodus_seg_build_t *b) {
    if (!b || b->scanning || b->h != b->last + 1u || !b->commit_done)
        return -1;
    char dat_tmp[NODUS_SEG_PATH_MAX], dat[NODUS_SEG_PATH_MAX];
    char idx_tmp[NODUS_SEG_PATH_MAX], idx[NODUS_SEG_PATH_MAX];
    char ok_tmp[NODUS_SEG_PATH_MAX], ok[NODUS_SEG_PATH_MAX];
    if (nodus_seg_path(b->dir, b->k, NODUS_SEG_F_DAT_TMP, dat_tmp,
                       sizeof(dat_tmp)) != 0 ||
        nodus_seg_path(b->dir, b->k, NODUS_SEG_F_DAT, dat, sizeof(dat)) != 0 ||
        nodus_seg_path(b->dir, b->k, NODUS_SEG_F_IDX_TMP, idx_tmp,
                       sizeof(idx_tmp)) != 0 ||
        nodus_seg_path(b->dir, b->k, NODUS_SEG_F_IDX, idx, sizeof(idx)) != 0 ||
        nodus_seg_path(b->dir, b->k, NODUS_SEG_F_OK_TMP, ok_tmp,
                       sizeof(ok_tmp)) != 0 ||
        nodus_seg_path(b->dir, b->k, NODUS_SEG_F_OK, ok, sizeof(ok)) != 0)
        return -1;

    /* the index */
    uint8_t *x = b->idx;
    tag16(NODUS_SEG_INDEX_TAG, x);
    put64(x + 16, b->k);
    put32(x + 24, NODUS_SEG_COUNT);
    {
        uint8_t *t = x + 28u + (size_t)NODUS_SEG_COUNT *
                                NODUS_SEG_INDEX_ENTRY_LEN;
        put64(t, b->commit_off);
        put32(t + 8, b->commit_len);
        put64(t + 12, b->size);
    }
    uint8_t mark[NODUS_SEG_DONE_LEN];
    tag16(NODUS_SEG_DONE_TAG, mark);
    put64(mark + 16, b->k);
    put64(mark + 24, b->size);
    put64(mark + 32, (uint64_t)NODUS_SEG_INDEX_LEN);
    mark[40] = b->flags;
    if (qgp_sha3_512(x, NODUS_SEG_INDEX_LEN, mark + 41) != 0) return -1;

    if (ftruncate(b->fd, (off_t)b->size) != 0 || fsync(b->fd) != 0 ||
        write_file_sync(idx_tmp, x, NODUS_SEG_INDEX_LEN) != 0 ||
        rename(dat_tmp, dat) != 0 || rename(idx_tmp, idx) != 0 ||
        fsync_dir(b->dir) != 0 ||
        write_file_sync(ok_tmp, mark, sizeof(mark)) != 0 ||
        rename(ok_tmp, ok) != 0 || fsync_dir(b->dir) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "segment %" PRIu64 ": publish failed: %s",
                      b->k, strerror(errno));
        return -1;
    }
    QGP_LOG_INFO(LOG_TAG, "segment %" PRIu64 " complete and published: %"
                 PRIu64 " bytes, terminal commit %s", b->k, b->size,
                 (b->flags & NODUS_SEG_FLAG_SIGS)
                     ? "signatures verified"
                     : "hash-bound only (signatures NOT verified)");
    build_close(b);
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Reading
 * ════════════════════════════════════════════════════════════════════ */

struct nodus_seg_reader {
    int      fd;                         /* .dat                          */
    uint64_t k, first, last;
    uint64_t data_size;
    uint8_t  flags;
    uint64_t commit_off;
    uint32_t commit_len;
    uint8_t *idx;                        /* the whole index               */
};

void nodus_seg_reader_close(nodus_seg_reader_t *r) {
    if (!r) return;
    if (r->fd >= 0) close(r->fd);
    free(r->idx);
    free(r);
}

int nodus_seg_reader_open(const char *dir, uint64_t k,
                          nodus_seg_reader_t **out) {
    if (!out) return -1;
    *out = NULL;
    if (!dir || k == 0 || k > ((uint64_t)INT64_MAX - 1u) / SEG_P - 1u)
        return -1;
    char okp[NODUS_SEG_PATH_MAX], idxp[NODUS_SEG_PATH_MAX];
    char datp[NODUS_SEG_PATH_MAX];
    if (nodus_seg_path(dir, k, NODUS_SEG_F_OK, okp, sizeof(okp)) != 0 ||
        nodus_seg_path(dir, k, NODUS_SEG_F_IDX, idxp, sizeof(idxp)) != 0 ||
        nodus_seg_path(dir, k, NODUS_SEG_F_DAT, datp, sizeof(datp)) != 0)
        return -1;

    uint8_t mark[NODUS_SEG_DONE_LEN + 1];
    int fd = open(okp, O_RDONLY);
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    ssize_t n = read(fd, mark, sizeof(mark));
    close(fd);
    uint8_t want_tag[NODUS_SEG_TAG_LEN];
    tag16(NODUS_SEG_DONE_TAG, want_tag);
    if (n != (ssize_t)NODUS_SEG_DONE_LEN ||
        memcmp(mark, want_tag, NODUS_SEG_TAG_LEN) != 0 ||
        get64(mark + 16) != k ||
        get64(mark + 32) != (uint64_t)NODUS_SEG_INDEX_LEN ||
        (mark[40] & (uint8_t)~NODUS_SEG_FLAG_SIGS) != 0)
        return 1;

    nodus_seg_reader_t *r = calloc(1, sizeof(*r));
    if (!r) return -1;
    r->fd = -1;
    r->k = k;
    r->first = (k - 1u) * SEG_P + 1u;
    r->last = k * SEG_P;
    r->data_size = get64(mark + 24);
    r->flags = mark[40];
    r->idx = malloc(NODUS_SEG_INDEX_LEN);
    if (!r->idx) { nodus_seg_reader_close(r); return -1; }

    int ret = 1;
    struct stat st;
    fd = open(idxp, O_RDONLY);
    if (fd < 0) { ret = errno == ENOENT ? 1 : -1; goto bad; }
    if (fstat(fd, &st) != 0 ||
        (uint64_t)st.st_size != (uint64_t)NODUS_SEG_INDEX_LEN ||
        pread_all(fd, r->idx, NODUS_SEG_INDEX_LEN, 0) != 0) {
        close(fd);
        goto bad;
    }
    close(fd);
    {
        uint8_t hx[64];
        if (qgp_sha3_512(r->idx, NODUS_SEG_INDEX_LEN, hx) != 0) {
            ret = -1;
            goto bad;
        }
        if (memcmp(hx, mark + 41, 64) != 0) goto bad;
    }
    tag16(NODUS_SEG_INDEX_TAG, want_tag);
    {
        const uint8_t *t = r->idx + 28u + (size_t)NODUS_SEG_COUNT *
                                          NODUS_SEG_INDEX_ENTRY_LEN;
        if (memcmp(r->idx, want_tag, NODUS_SEG_TAG_LEN) != 0 ||
            get64(r->idx + 16) != k || get32(r->idx + 24) != NODUS_SEG_COUNT ||
            get64(t + 12) != r->data_size)
            goto bad;
        r->commit_off = get64(t);
        r->commit_len = get32(t + 8);
        if (r->commit_len == 0 || r->commit_len > NODUS_SEG_COMMIT_MAX ||
            r->commit_off > r->data_size ||
            r->data_size - r->commit_off != r->commit_len)
            goto bad;
    }
    r->fd = open(datp, O_RDONLY);
    if (r->fd < 0) { ret = errno == ENOENT ? 1 : -1; goto bad; }
    if (fstat(r->fd, &st) != 0 || (uint64_t)st.st_size != r->data_size)
        goto bad;
    *out = r;
    return 0;
bad:
    if (ret == 1)
        QGP_LOG_WARN(LOG_TAG, "segment %" PRIu64 ": marker does not agree "
                     "with the files — not held", k);
    nodus_seg_reader_close(r);
    return ret;
}

int nodus_seg_held(const char *dir, uint64_t k) {
    nodus_seg_reader_t *r = NULL;
    int rc = nodus_seg_reader_open(dir, k, &r);
    nodus_seg_reader_close(r);
    return rc == 0 ? 1 : (rc == 1 ? 0 : -1);
}

uint8_t nodus_seg_reader_flags(const nodus_seg_reader_t *r) {
    return r ? r->flags : 0;
}

int nodus_seg_reader_get(nodus_seg_reader_t *r, uint64_t h,
                         uint8_t *hdr, size_t *hdr_len,
                         uint32_t *n_parts, uint32_t part_i,
                         uint8_t *part, size_t *part_len) {
    if (!r || !n_parts) return -1;
    if (h < r->first || h > r->last) return 1;
    const uint8_t *e = r->idx + 28u + (h - r->first) *
                                      NODUS_SEG_INDEX_ENTRY_LEN;
    uint64_t off = get64(e);
    const uint32_t n = get32(e + 8);
    if (n == 0 || n > CMT_PART_SET_MAX_PARTS || off >= r->data_size)
        return -1;
    uint8_t pre[12];
    if (pread_all(r->fd, pre, 12, off) != 0 || get64(pre) != h) return -1;
    const uint32_t hl = get32(pre + 8);
    if (hl == 0 || hl > NODUS_SEG_HEADER_MAX) return -1;
    off += 12;
    if (hdr) {
        if (!hdr_len || pread_all(r->fd, hdr, hl, off) != 0) return -1;
        *hdr_len = hl;
    }
    off += hl;
    uint8_t np[4];
    if (pread_all(r->fd, np, 4, off) != 0 || get32(np) != n) return -1;
    off += 4;
    *n_parts = n;
    if (!part) return 0;
    if (!part_len) return -1;
    if (part_i >= n) return 1;
    for (uint32_t j = 0;; j++) {
        uint8_t pl[4];
        if (pread_all(r->fd, pl, 4, off) != 0) return -1;
        const uint32_t plen = get32(pl);
        if (plen == 0 || plen > NODUS_SEG_PART_PROTO_MAX ||
            off + 4u + plen > r->data_size)
            return -1;
        off += 4;
        if (j == part_i) {
            if (pread_all(r->fd, part, plen, off) != 0) return -1;
            *part_len = plen;
            return 0;
        }
        off += plen;
    }
}

int nodus_seg_reader_commit(nodus_seg_reader_t *r, uint8_t *out, size_t cap,
                            size_t *len) {
    if (!r || !out || !len || cap < r->commit_len) return -1;
    if (pread_all(r->fd, out, r->commit_len, r->commit_off) != 0) return -1;
    *len = r->commit_len;
    return 0;
}

/* ══════════════════════════════════════════════════════════════════════
 * Helpers
 * ════════════════════════════════════════════════════════════════════ */

int nodus_seg_part_split(const uint8_t *proto, size_t len,
                         uint8_t *part_out, size_t *part_len,
                         uint8_t *proof_out, size_t *proof_len,
                         uint32_t *index_out) {
    if (!proto || !part_out || !part_len || !proof_out || !proof_len ||
        len == 0 || len > NODUS_SEG_PART_PROTO_MAX)
        return -1;
    int ret = -1;
    cmt_part_t *pt = malloc(sizeof(*pt));
    uint8_t *ab = malloc(CMT_BLOCK_PART_SIZE_BYTES);
    if (!pt || !ab) goto done;
    cmt_pb_arena_t ar = { ab, CMT_BLOCK_PART_SIZE_BYTES, 0 };
    if (cmt_pb_part_unmarshal(proto, len, pt, &ar) != CMT_OK ||
        pt->bytes.len > CMT_BLOCK_PART_SIZE_BYTES)
        goto done;
    size_t pl = 0;
    if (cmt_pb_proof_marshal(&pt->proof, proof_out, NODUS_STPROBE_PROOF_MAX,
                             &pl) != CMT_OK || pl == 0)
        goto done;
    if (pt->bytes.len) memcpy(part_out, pt->bytes.data, pt->bytes.len);
    *part_len = pt->bytes.len;
    *proof_len = pl;
    if (index_out) *index_out = pt->index;
    ret = 0;
done:
    free(ab);
    free(pt);
    return ret;
}

int nodus_seg_delete(const char *dir, uint64_t k) {
    static const nodus_seg_file_t order[6] = {
        NODUS_SEG_F_OK, NODUS_SEG_F_OK_TMP, NODUS_SEG_F_IDX,
        NODUS_SEG_F_IDX_TMP, NODUS_SEG_F_DAT, NODUS_SEG_F_DAT_TMP
    };
    int ret = 0;
    for (size_t i = 0; i < 6; i++) {
        char p[NODUS_SEG_PATH_MAX];
        if (nodus_seg_path(dir, k, order[i], p, sizeof(p)) != 0 ||
            unlink_quiet(p) != 0)
            ret = -1;
    }
    if (fsync_dir(dir) != 0) ret = -1;
    return ret;
}
