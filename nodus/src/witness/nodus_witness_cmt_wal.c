/**
 * @file nodus_witness_cmt_wal.c
 * @brief cometbft @709fd12b consensus/wal.go over the libs/autofile file
 *        group. Contract and citations: nodus_witness_cmt_wal.h.
 */

#include "witness/nodus_witness_cmt_wal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypto/hash/qgp_sha3.h"     /* the SQLite-era row digest (carry) */
#include "crypto/utils/qgp_log.h"
#include "dnac/cmt_msgs.h"           /* cmt_msg_validate_basic (msgs.go:232) */

#define LOG_TAG "W_CMTWAL"

/* Decode outcomes (wal.go:366-420). */
#define WAL_DEC_OK       0   /* a record                                  */
#define WAL_DEC_EOF      1   /* io.EOF while reading the CRC (:369-371)   */
#define WAL_DEC_CORRUPT  2   /* DataCorruptionError (:339-349)            */
#define WAL_DEC_IO     (-1)  /* an OS error (header: CORRUPTION deviation) */
#define WAL_DEC_FAULT  (-2)  /* a failed allocation or a NULL             */

/* ══ crc32 (Go 1.21.5 hash/crc32/crc32_generic.go) ══════════════════════ */

void nodus_cmt_crc32_make_table(uint32_t poly, nodus_cmt_crc32_table_t tab)
{
    for (uint32_t i = 0; i < 256u; i++) {                /* :27 */
        uint32_t crc = i;                                /* :28 */

        for (int j = 0; j < 8; j++) {                    /* :29-35 */
            if ((crc & 1u) == 1u) {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
        tab[i] = crc;                                    /* :36 */
    }
}

uint32_t nodus_cmt_crc32_update(uint32_t crc,
                                const nodus_cmt_crc32_table_t tab,
                                const uint8_t *p, size_t n)
{
    crc = ~crc;                                          /* :43 */
    for (size_t i = 0; i < n; i++) {                     /* :44-46 */
        crc = tab[(uint8_t)crc ^ p[i]] ^ (crc >> 8);
    }
    return ~crc;                                         /* :47 */
}

static void put_be32(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

/* ══ open / start / close ═══════════════════════════════════════════════ */

/* cmtos.EnsureDir (libs/os/os.go:50-56) → Go's os.MkdirAll(dir, mode):
 * every missing component is created with `mode`; an existing directory
 * is success, an existing non-directory is an error. */
static int wal_ensure_dir(const char *dir, mode_t mode)
{
    char   buf[NODUS_CMT_AUTOFILE_PATH_MAX];
    size_t len = strlen(dir);

    if (len == 0 || len >= sizeof(buf)) {
        return CMT_FAULT;
    }
    memcpy(buf, dir, len + 1);
    for (size_t i = 1; i <= len; i++) {
        if (buf[i] == '/' || buf[i] == '\0') {
            struct stat st;
            char        save = buf[i];

            buf[i] = '\0';
            if (mkdir(buf, mode) != 0 && errno != EEXIST) {
                QGP_LOG_ERROR(LOG_TAG, "could not create directory %s: %s",
                              buf, strerror(errno));
                return CMT_FAULT;
            }
            if (stat(buf, &st) != 0 || !S_ISDIR(st.st_mode)) {
                QGP_LOG_ERROR(LOG_TAG, "%s is not a directory", buf);
                return CMT_FAULT;
            }
            buf[i] = save;
        }
    }
    return CMT_OK;
}

static void wal_release(nodus_cmt_wal_t *w)
{
    if (w->cursor) {
        nodus_cmt_group_reader_close(w->cursor);
        free(w->cursor);
        w->cursor = NULL;
    }
    w->cursor_valid = false;
    nodus_cmt_group_close(&w->group);
    free(w->stamp);
    w->stamp = NULL;
    free(w->enc_buf);
    w->enc_buf = NULL;
    w->enc_cap = 0;
    free(w->dec_buf);
    w->dec_buf = NULL;
    free(w->read_arena.buf);
    w->read_arena.buf = NULL;
    w->read_arena.cap = w->read_arena.used = 0;
    w->started = false;
    w->flush_armed = false;
}

int nodus_cmt_wal_open(nodus_cmt_wal_t *w, const char *wal_file,
                       cmt_now_fn now, void *now_ctx)
{
    char        dir[NODUS_CMT_AUTOFILE_PATH_MAX];
    const char *slash;
    size_t      dl;
    size_t      pl;

    if (!w || !wal_file || !wal_file[0] || !now) {
        return CMT_FAULT;
    }
    pl = strlen(wal_file);
    if (pl >= sizeof(w->path)) {
        return CMT_FAULT;
    }
    memset(w, 0, sizeof(*w));
    memcpy(w->path, wal_file, pl + 1);
    w->now = now;
    w->now_ctx = now_ctx;
    w->flush_interval_ns = NODUS_CMT_WAL_FLUSH_INTERVAL_NS;       /* :104 */
    nodus_cmt_crc32_make_table(NODUS_CMT_CRC32C_POLY, w->crc32c); /* replay.go:20 */

    /* :92 EnsureDir(filepath.Dir(walFile), 0o700) */
    slash = strrchr(wal_file, '/');
    if (slash && slash != wal_file) {
        dl = (size_t)(slash - wal_file);
        if (dl >= sizeof(dir)) {
            return CMT_FAULT;
        }
        memcpy(dir, wal_file, dl);
        dir[dl] = '\0';
        if (wal_ensure_dir(dir, 0700) != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "failed to ensure WAL directory "
                          "is in place");
            return CMT_FAULT;
        }
    }

    /* :97 auto.OpenGroup(walFile) — no group option: the reference's
     * default limits (group.go:21-22), as state.go:453 opens it. */
    if (nodus_cmt_group_open(&w->group, wal_file) != CMT_OK) {
        return CMT_FAULT;
    }

    w->enc_cap = NODUS_CMT_WAL_RECORD_HEADER_LEN +
                 (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES;
    w->enc_buf = (uint8_t *)malloc(w->enc_cap);
    w->dec_buf = (uint8_t *)malloc((size_t)CMT_WAL_MAX_MSG_SIZE_BYTES);
    w->read_arena.cap = (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES;
    w->read_arena.buf = (uint8_t *)malloc(w->read_arena.cap);
    w->read_arena.used = 0;
    w->stamp = (cmt_timed_wal_message_t *)malloc(sizeof(*w->stamp));
    w->cursor = (nodus_cmt_group_reader_t *)calloc(1, sizeof(*w->cursor));
    if (w->cursor) {
        w->cursor->cur_fd = -1;      /* calloc's 0 is stdin, not ours */
    }
    if (!w->enc_buf || !w->dec_buf || !w->read_arena.buf || !w->stamp ||
        !w->cursor) {
        wal_release(w);
        return CMT_FAULT;
    }
    QGP_LOG_INFO(LOG_TAG, "consensus WAL %s open (files %d..%d, head limit "
                 "%lld, total limit %lld)", wal_file, w->group.min_index,
                 w->group.max_index, (long long)w->group.head_size_limit,
                 (long long)w->group.total_size_limit);
    return CMT_OK;
}

static int wal_now_ns(nodus_cmt_wal_t *w, int64_t *out)
{
    cmt_time_t t;

    if (w->now(w->now_ctx, &t) != CMT_OK) {
        return CMT_FAULT;
    }
    *out = cmt_time_unix_nano(t);
    return CMT_OK;
}

/* pread(2) of exactly `n` bytes at `off`, retrying EINTR and short reads;
 * reaching the file's end first is CMT_FAULT (the caller sized the read
 * from fstat). */
static int wal_pread_all(int fd, uint8_t *p, size_t n, int64_t off)
{
    size_t done = 0;

    while (done < n) {
        ssize_t k = pread(fd, p + done, n - done, (off_t)(off + (int64_t)done));

        if (k < 0) {
            if (errno == EINTR) {
                continue;
            }
            return CMT_FAULT;
        }
        if (k == 0) {
            return CMT_FAULT;
        }
        done += (size_t)k;
    }
    return CMT_OK;
}

/* HARDENING — decision 2026-09-27-p2p-fix-2.md 1(a); no reference
 * counterpart. The reference appends behind whatever the head ends with
 * (wal.go:124-133 OnStart, group.go:204-208 Write): a record cut short by
 * a crash (1-7 header bytes, or a body shorter than its length) stays in
 * the file, and when it is 1-3 CRC bytes its Decode is a clean io.EOF
 * (wal.go:369-371), so the next record is appended BEHIND the torn bytes
 * and every later read is misaligned.
 *
 * Here, once per start and before the first append, the head is walked
 * record by record from offset 0 on the 8-byte headers:
 *   · fewer than 8 bytes left, or a length 1..CMT_WAL_MAX_MSG_SIZE_BYTES
 *     that runs past the end of the file — a TORN TAIL: the head is
 *     truncated to the end of the last complete, checksum-valid record
 *     and fsynced (nodus_cmt_autofile_truncate);
 *   · a length of 0 or above the bound, or a complete record whose
 *     crc32c does not match — CORRUPTION, not a torn tail: the walk
 *     stops and nothing is changed; the replay reports it and repairs
 *     (state.go:338-386), exactly as before;
 *   · the end of the file on a record boundary — clean, nothing changed.
 * The read side (wal_decode, SearchForEndHeight, read_next) is untouched;
 * a file with no torn tail is not written. */
static int wal_trim_torn_tail(nodus_cmt_wal_t *w)
{
    int64_t size = -1;
    int64_t off = 0;
    int64_t cut = -1;
    int     fd;
    int     rc = CMT_OK;

    if (nodus_cmt_autofile_size(&w->group.head, &size) != CMT_OK) {
        return CMT_FAULT;
    }
    if (size == 0) {
        return CMT_OK;
    }
    do {
        fd = open(w->path, O_RDONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "torn-tail check: open %s: %s", w->path,
                      strerror(errno));
        return CMT_FAULT;
    }
    while (off < size) {
        int64_t  rem = size - off;
        uint8_t  hdr[NODUS_CMT_WAL_RECORD_HEADER_LEN];
        uint32_t crc, length;

        if (rem < (int64_t)NODUS_CMT_WAL_RECORD_HEADER_LEN) {
            cut = off;                                   /* torn header */
            break;
        }
        if (wal_pread_all(fd, hdr, sizeof(hdr), off) != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "torn-tail check: read %s at %lld: %s",
                          w->path, (long long)off, strerror(errno));
            rc = CMT_FAULT;
            break;
        }
        crc = get_be32(hdr);
        length = get_be32(hdr + 4);
        if (length == 0 || length > (uint32_t)CMT_WAL_MAX_MSG_SIZE_BYTES) {
            break;                                       /* corruption */
        }
        if ((int64_t)length > rem - (int64_t)NODUS_CMT_WAL_RECORD_HEADER_LEN) {
            cut = off;                                   /* torn body */
            break;
        }
        if (wal_pread_all(fd, w->dec_buf, (size_t)length,
                          off + (int64_t)NODUS_CMT_WAL_RECORD_HEADER_LEN)
            != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "torn-tail check: read %s at %lld: %s",
                          w->path, (long long)off, strerror(errno));
            rc = CMT_FAULT;
            break;
        }
        if (nodus_cmt_crc32_update(0, w->crc32c, w->dec_buf,
                                   (size_t)length) != crc) {
            break;                                       /* corruption */
        }
        off += (int64_t)NODUS_CMT_WAL_RECORD_HEADER_LEN + (int64_t)length;
    }
    (void)close(fd);
    if (rc != CMT_OK || cut < 0) {
        return rc;
    }
    QGP_LOG_WARN(LOG_TAG, "consensus WAL %s ends with a torn record: "
                 "truncating from %lld to %lld bytes (the last complete "
                 "record) before the first append", w->path, (long long)size,
                 (long long)cut);
    return nodus_cmt_autofile_truncate(&w->group.head, cut);
}

int nodus_cmt_wal_start(nodus_cmt_wal_t *w)
{
    int64_t size = -1;
    int64_t now_ns = 0;

    if (!w || !w->group.head_buf) {
        return CMT_FAULT;
    }
    if (w->started) {
        return CMT_FAULT;                    /* service: already started */
    }
    /* HARDENING 1(a), before OnStart's own write (header: TORN TAIL) */
    if (wal_trim_torn_tail(w) != CMT_OK) {
        return CMT_FAULT;
    }
    /* :125-132 */
    if (nodus_cmt_autofile_size(&w->group.head, &size) != CMT_OK) {
        return CMT_FAULT;
    }
    if (size == 0) {
        cmt_wal_message_t *m = (cmt_wal_message_t *)calloc(1, sizeof(*m));
        int                rc;

        if (!m) {
            return CMT_FAULT;
        }
        m->kind = CMT_PB_WAL_END_HEIGHT;
        m->u.end_height.height = 0;                      /* :129 */
        rc = nodus_cmt_wal_write_sync(w, m);
        free(m);
        if (rc != CMT_OK) {
            return CMT_FAULT;
        }
    }
    if (wal_now_ns(w, &now_ns) != CMT_OK) {
        return CMT_FAULT;
    }
    nodus_cmt_group_start(&w->group, now_ns);            /* :133 */
    w->flush_armed = true;                               /* :137 */
    w->flush_deadline_ns = now_ns + w->flush_interval_ns;
    w->started = true;
    return CMT_OK;
}

void nodus_cmt_wal_close(nodus_cmt_wal_t *w)
{
    if (!w) {
        return;
    }
    if (w->started) {
        w->flush_armed = false;                          /* :165 */
        if (nodus_cmt_wal_flush_and_sync(w) != CMT_OK) { /* :166-168 */
            QGP_LOG_ERROR(LOG_TAG, "%s", "error on flush data to disk");
        }
        nodus_cmt_group_stop(&w->group);                 /* :169-171 */
    }
    wal_release(w);                                      /* :172 Close */
}

/* ══ the write classes ══════════════════════════════════════════════════ */

/* wal.go:301-326 — `Encode` up to the write: WALToProto + Marshal, the
 * size check, crc32c and the 8-byte header, into w->enc_buf.
 * `*out_len` is the whole record's length. */
static int wal_frame(nodus_cmt_wal_t *w, const cmt_timed_wal_message_t *v,
                     size_t *out_len)
{
    size_t   plen = 0;
    uint32_t crc;
    int      rc;

    /* :302-311 WALToProto + Marshal — the port's encoder refuses a `P`
     * that does not fit CMT_WAL_MAX_MSG_SIZE_BYTES, which is :318-320's
     * "msg is too big" as the same refusal. */
    rc = cmt_timed_wal_message_encode(v,
                                      w->enc_buf + NODUS_CMT_WAL_RECORD_HEADER_LEN,
                                      (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES,
                                      &plen);
    if (rc != CMT_OK) {
        return rc;
    }
    if (plen > (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES) {     /* :318-320 */
        QGP_LOG_ERROR(LOG_TAG, "msg is too big: %zu bytes, max: %d bytes",
                      plen, (int)CMT_WAL_MAX_MSG_SIZE_BYTES);
        return CMT_REJECT;
    }
    crc = nodus_cmt_crc32_update(0, w->crc32c,           /* :316 */
                                 w->enc_buf + NODUS_CMT_WAL_RECORD_HEADER_LEN,
                                 plen);
    put_be32(w->enc_buf, crc);                           /* :324 */
    put_be32(w->enc_buf + 4, (uint32_t)plen);            /* :325 */
    *out_len = NODUS_CMT_WAL_RECORD_HEADER_LEN + plen;
    return CMT_OK;
}

/* wal.go:301-330 `Encode` into the head buffer. */
static int wal_encode(nodus_cmt_wal_t *w, const cmt_timed_wal_message_t *v)
{
    size_t len = 0;
    int    rc = wal_frame(w, v, &len);

    if (rc != CMT_OK) {
        return rc;
    }
    /* :328 enc.wr.Write(msg) — the group's buffered Write */
    if (nodus_cmt_group_write(&w->group, w->enc_buf, len) != CMT_OK) {
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_wal_write(void *ctx, const cmt_wal_message_t *msg)
{
    nodus_cmt_wal_t *w = (nodus_cmt_wal_t *)ctx;
    int              rc;

    if (!w || !w->stamp || !msg) {
        return CMT_FAULT;
    }
    /* :189 &TimedWALMessage{cmttime.Now(), msg} */
    if (w->now(w->now_ctx, &w->stamp->time) != CMT_OK) {
        return CMT_FAULT;
    }
    w->stamp->msg = *msg;
    rc = wal_encode(w, w->stamp);
    if (rc != CMT_OK) {                                  /* :189-193 */
        QGP_LOG_ERROR(LOG_TAG, "Error writing msg to consensus wal. "
                      "WARNING: recover may not be possible for the "
                      "current height (kind %d, rc %d)", (int)msg->kind, rc);
        return rc;
    }
    return CMT_OK;
}

int nodus_cmt_wal_write_sync(void *ctx, const cmt_wal_message_t *msg)
{
    nodus_cmt_wal_t *w = (nodus_cmt_wal_t *)ctx;

    if (nodus_cmt_wal_write(w, msg) != CMT_OK) {         /* :206-208 */
        return CMT_FAULT;
    }
    if (nodus_cmt_wal_flush_and_sync(w) != CMT_OK) {     /* :210-215 */
        QGP_LOG_ERROR(LOG_TAG, "%s", "WriteSync failed to flush consensus "
                      "wal. WARNING: may result in creating alternative "
                      "proposals / votes for the current height iff the "
                      "node restarted");
        return CMT_FAULT;
    }
    return CMT_OK;
}

int nodus_cmt_wal_flush_and_sync(void *ctx)
{
    nodus_cmt_wal_t *w = (nodus_cmt_wal_t *)ctx;

    if (!w) {
        return CMT_FAULT;
    }
    return nodus_cmt_group_flush_and_sync(&w->group);    /* :158 */
}

/* ══ the tickers ════════════════════════════════════════════════════════ */

bool nodus_cmt_wal_next_flush_deadline(const nodus_cmt_wal_t *w,
                                       int64_t *out_deadline_ns)
{
    if (!w || !w->flush_armed) {
        return false;
    }
    if (out_deadline_ns) {
        *out_deadline_ns = w->flush_deadline_ns;
    }
    return true;
}

int nodus_cmt_wal_flush_if_due(nodus_cmt_wal_t *w, int64_t now_ns)
{
    int64_t period;
    int     rc;

    if (!w) {
        return CMT_FAULT;
    }
    if (!w->flush_armed || now_ns < w->flush_deadline_ns) {
        return CMT_OK;
    }
    /* Go 1.21.5 runtime/time.go:854-857 — the ticker's next `when`. */
    period = w->flush_interval_ns;
    if (period > 0) {
        int64_t delta = w->flush_deadline_ns - now_ns;

        w->flush_deadline_ns += period * (1 + -delta / period);
    }
    rc = nodus_cmt_wal_flush_and_sync(w);                /* :145-148 */
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "Periodic WAL flush failed");
    }
    return rc;
}

bool nodus_cmt_wal_next_group_check_deadline(const nodus_cmt_wal_t *w,
                                             int64_t *out_deadline_ns)
{
    if (!w) {
        return false;
    }
    return nodus_cmt_group_next_check_deadline(&w->group, out_deadline_ns);
}

int nodus_cmt_wal_group_check_if_due(nodus_cmt_wal_t *w, int64_t now_ns)
{
    if (!w) {
        return CMT_FAULT;
    }
    return nodus_cmt_group_check_if_due(&w->group, now_ns);
}

/* ══ the read side ══════════════════════════════════════════════════════ */

/* Map a GroupReader result that is not OK: EOF and "given empty slice"
 * are errors the reference wraps as DataCorruptionError (:380-381,
 * :393-396); an OS error is the stated deviation (WAL_DEC_IO). */
static int wal_dec_err(int grc)
{
    return (grc == NODUS_CMT_GROUP_READ_IO) ? WAL_DEC_IO : WAL_DEC_CORRUPT;
}

/* wal.go:366-420 `Decode` from `gr`. On WAL_DEC_OK `*out` is filled and
 * its payloads live in `w->read_arena`. */
static int wal_decode(nodus_cmt_wal_t *w, nodus_cmt_group_reader_t *gr,
                      cmt_timed_wal_message_t *out)
{
    uint8_t  b[4];
    size_t   n = 0;
    uint32_t crc, length, actual;
    int      grc;
    int      rc;

    /* :367-376 — the CRC. io.EOF with ANY count (0-3 bytes) is EOF,
     * `errors.Is(err, io.EOF)` at :370. */
    grc = nodus_cmt_group_reader_read(gr, b, 4, &n);
    if (grc == NODUS_CMT_GROUP_READ_EOF) {
        return WAL_DEC_EOF;
    }
    if (grc != NODUS_CMT_GROUP_READ_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "DataCorruptionError[failed to read "
                      "checksum]");
        return wal_dec_err(grc);
    }
    crc = get_be32(b);

    /* :378-383 — the length */
    grc = nodus_cmt_group_reader_read(gr, b, 4, &n);
    if (grc != NODUS_CMT_GROUP_READ_OK) {
        QGP_LOG_ERROR(LOG_TAG, "DataCorruptionError[failed to read length "
                      "(read %zu)]", n);
        return wal_dec_err(grc);
    }
    length = get_be32(b);

    /* :385-390 */
    if (length > (uint32_t)CMT_WAL_MAX_MSG_SIZE_BYTES) {
        QGP_LOG_ERROR(LOG_TAG, "DataCorruptionError[length %u exceeded "
                      "maximum possible value of %d bytes]", length,
                      (int)CMT_WAL_MAX_MSG_SIZE_BYTES);
        return WAL_DEC_CORRUPT;
    }

    /* :392-396 — a zero length reads an empty slice, which GroupReader
     * refuses ("given empty slice", group.go:462-464): corruption. */
    grc = nodus_cmt_group_reader_read(gr, w->dec_buf, (size_t)length, &n);
    if (grc != NODUS_CMT_GROUP_READ_OK) {
        QGP_LOG_ERROR(LOG_TAG, "DataCorruptionError[failed to read data "
                      "(read: %zu, wanted: %u)]", n, length);
        return wal_dec_err(grc);
    }

    /* :398-402 */
    actual = nodus_cmt_crc32_update(0, w->crc32c, w->dec_buf, (size_t)length);
    if (actual != crc) {
        QGP_LOG_ERROR(LOG_TAG, "DataCorruptionError[checksums do not "
                      "match: read: %u, actual: %u]", crc, actual);
        return WAL_DEC_CORRUPT;
    }

    /* :404-413 Unmarshal + WALFromProto */
    w->read_arena.used = 0;
    rc = cmt_timed_wal_message_decode(w->dec_buf, (size_t)length, out,
                                      &w->read_arena);
    if (rc == CMT_FAULT) {
        return WAL_DEC_FAULT;
    }
    if (rc != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "DataCorruptionError[failed to decode data "
                      "(rc %d)]", rc);
        return WAL_DEC_CORRUPT;
    }
    /* :410-413 → msgs.go:316 MsgFromProto, whose last act is
     * `pb.ValidateBasic()` (msgs.go:232-234); cmt_msg_from_proto stops
     * short of it (cmt_msgs.h), so it runs here. A failure is a
     * DataCorruptionError at :411-413. */
    if (out->msg.kind == CMT_PB_WAL_MSG_INFO) {
        rc = cmt_msg_validate_basic(&out->msg.u.msg_info.msg);
        if (rc == CMT_FAULT) {
            return WAL_DEC_FAULT;
        }
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "DataCorruptionError[failed to convert "
                          "from proto: ValidateBasic (kind %d)]",
                          (int)out->msg.u.msg_info.msg.kind);
            return WAL_DEC_CORRUPT;
        }
    }
    return WAL_DEC_OK;                                   /* :414-419 */
}

int nodus_cmt_wal_search_end_height(void *ctx, int64_t height,
                                    bool *out_found)
{
    nodus_cmt_wal_t         *w = (nodus_cmt_wal_t *)ctx;
    cmt_timed_wal_message_t *msg;
    int64_t                  last_height_found = -1;     /* :239 */
    int                      index;

    if (!w || !w->cursor || !out_found) {
        return CMT_FAULT;
    }
    *out_found = false;
    nodus_cmt_group_reader_close(w->cursor);
    w->cursor_valid = false;

    msg = (cmt_timed_wal_message_t *)malloc(sizeof(*msg));
    if (!msg) {
        return CMT_FAULT;
    }
    /* :241-245 — newest file first */
    QGP_LOG_INFO(LOG_TAG, "Searching for height %lld (min %d, max %d)",
                 (long long)height, w->group.min_index, w->group.max_index);
    for (index = w->group.max_index; index >= w->group.min_index; index--) {
        int grc = nodus_cmt_group_new_reader(&w->group, index, w->cursor);

        if (grc != NODUS_CMT_GROUP_READ_OK) {            /* :246-249 */
            nodus_cmt_group_reader_close(w->cursor);
            free(msg);
            QGP_LOG_ERROR(LOG_TAG, "cannot open WAL file index %d", index);
            return CMT_FAULT;
        }
        for (;;) {                                       /* :252 */
            int drc = wal_decode(w, w->cursor, msg);     /* :253 */

            if (drc == WAL_DEC_EOF) {                    /* :254-262 */
                if (last_height_found > 0 && last_height_found < height) {
                    nodus_cmt_group_reader_close(w->cursor);
                    free(msg);
                    return CMT_OK;
                }
                break;
            }
            if (drc == WAL_DEC_CORRUPT) {                /* :263-266 */
                QGP_LOG_ERROR(LOG_TAG, "%s", "Corrupted entry. Skipping...");
                continue;
            }
            if (drc != WAL_DEC_OK) {                     /* :267-270 */
                nodus_cmt_group_reader_close(w->cursor);
                free(msg);
                return CMT_FAULT;
            }
            if (msg->msg.kind == CMT_PB_WAL_END_HEIGHT) {        /* :272 */
                last_height_found = msg->msg.u.end_height.height;
                if (last_height_found == height) {       /* :274-277 */
                    QGP_LOG_INFO(LOG_TAG, "Found height %lld (index %d)",
                                 (long long)height, index);
                    w->cursor_valid = true;
                    *out_found = true;
                    free(msg);
                    return CMT_OK;
                }
            }
        }
        nodus_cmt_group_reader_close(w->cursor);         /* :280 */
    }
    free(msg);
    return CMT_OK;                                       /* :283 */
}

int nodus_cmt_wal_read_next(void *ctx, cmt_timed_wal_message_t *out,
                            bool *out_eof)
{
    nodus_cmt_wal_t *w = (nodus_cmt_wal_t *)ctx;
    int              drc;

    if (!w || !w->cursor || !out || !out_eof) {
        return CMT_FAULT;
    }
    *out_eof = false;
    if (!w->cursor_valid) {
        /* no search: a GroupReader from the group's first file */
        if (nodus_cmt_group_new_reader(&w->group, w->group.min_index,
                                       w->cursor) != NODUS_CMT_GROUP_READ_OK) {
            nodus_cmt_group_reader_close(w->cursor);
            return CMT_FAULT;
        }
        w->cursor_valid = true;
    }
    drc = wal_decode(w, w->cursor, out);
    switch (drc) {
    case WAL_DEC_OK:
        return CMT_OK;
    case WAL_DEC_EOF:
        *out_eof = true;                                 /* replay.go:149-150 */
        return CMT_OK;
    case WAL_DEC_CORRUPT:
        /* replay.go:151-153 — "data has been corrupted in last height of
         * consensus WAL". CMT_REJECT is the row's DataCorruptionError and
         * only that (header: THE CORRUPTION CLASS); cmt_cs_start repairs
         * on it (state.go:338-386). */
        QGP_LOG_ERROR(LOG_TAG, "%s", "data has been corrupted in last "
                      "height of consensus WAL");
        return CMT_REJECT;
    default:
        return CMT_FAULT;
    }
}

/* ══ repair (state.go:352-385, :2621-2653) ═════════════════════════════ */

/* One whole buffer onto `fd`, retrying EINTR and short writes — Go's
 * File.Write (internal/poll/fd_unix.go:374-399, go1.21.5). */
static int wal_write_all(int fd, const uint8_t *p, size_t n)
{
    size_t done = 0;

    while (done < n) {
        ssize_t k = write(fd, p + done, n - done);

        if (k < 0) {
            if (errno == EINTR) {
                continue;
            }
            return CMT_FAULT;
        }
        if (k == 0) {
            return CMT_FAULT;
        }
        done += (size_t)k;
    }
    return CMT_OK;
}

/* libs/os/os.go:88-112 `CopyFile`: refuse a directory, create/truncate
 * the destination with the source's permission bits, copy everything.
 * HARDENING (decision 2026-09-27-p2p-fix-2.md 1(b); os.go:108 closes
 * without a sync): the copy is fsynced before it is closed, so the
 * `.CORRUPTED` backup is durable before the head is replaced. */
static int wal_copy_file(const char *src, const char *dst)
{
    uint8_t     buf[65536];
    struct stat st;
    int         in, out = -1;
    int         rc = CMT_FAULT;

    in = open(src, O_RDONLY | O_CLOEXEC);                    /* :89-93 */
    if (in < 0) {
        QGP_LOG_ERROR(LOG_TAG, "copy: open %s: %s", src, strerror(errno));
        return CMT_FAULT;
    }
    if (fstat(in, &st) != 0 || S_ISDIR(st.st_mode)) {        /* :95-101 */
        QGP_LOG_ERROR(LOG_TAG, "copy: %s is unreadable or a directory", src);
        goto done;
    }
    out = open(dst, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC,  /* :104 */
               st.st_mode & 0777);
    if (out < 0) {
        QGP_LOG_ERROR(LOG_TAG, "copy: create %s: %s", dst, strerror(errno));
        goto done;
    }
    for (;;) {                                               /* :110 io.Copy */
        ssize_t k = read(in, buf, sizeof(buf));

        if (k < 0) {
            if (errno == EINTR) {
                continue;
            }
            QGP_LOG_ERROR(LOG_TAG, "copy: read %s: %s", src, strerror(errno));
            goto done;
        }
        if (k == 0) {
            break;
        }
        if (wal_write_all(out, buf, (size_t)k) != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "copy: write %s: %s", dst, strerror(errno));
            goto done;
        }
    }
    if (fsync(out) != 0) {                                   /* HARDENING */
        QGP_LOG_ERROR(LOG_TAG, "copy: fsync %s: %s", dst, strerror(errno));
        goto done;
    }
    rc = CMT_OK;
done:
    if (out >= 0 && close(out) != 0 && rc == CMT_OK) {       /* :108 defer */
        QGP_LOG_ERROR(LOG_TAG, "copy: close %s: %s", dst, strerror(errno));
        rc = CMT_FAULT;
    }
    (void)close(in);                                         /* :93 defer  */
    return rc;
}

/* state.go:2619-2653 `repairWalFile(src, dst)` — "decodes messages from
 * src (until the decoder errors) and writes them to dst".
 *
 * The decoder is a WAL handle opened on `src` itself: its group's head is
 * `src`, and `readGroupInfo` over that name's prefix (group.go:374-399)
 * finds no indexed sibling, so the reader reads exactly that one file —
 * the reference's `NewWALDecoder(os.Open(src))`. Two observable
 * differences from reading an `*os.File`, both ending the loop at the
 * same record: a torn CRC is EOF here and a short read there, and a zero
 * length is "given empty slice" here and a CRC/unmarshal failure there —
 * the reference breaks on ANY error (:2641-2644), so the records kept are
 * the same. The handle opens `src` O_RDWR|O_APPEND (autofile.go:161)
 * where the reference opens it read-only; nothing is written to it.
 *
 * HARDENING — decision 2026-09-27-p2p-fix-2.md 1(b); no reference
 * counterpart. The reference's `os.Create(dst)` (:2628) truncates the
 * head FIRST and re-encodes into it, so a crash in between leaves an
 * empty or half-written head. Here the kept records go to `tmp` (same
 * directory, a stale one removed first, created O_EXCL), which is
 * fsynced, closed, renamed over `dst`, and the directory fsynced: a crash
 * at any step leaves either the old head or the complete repaired one.
 * When NO record survives, the temp file gets `EndHeight{0}` (stamped
 * now) — the byte state the reference reaches one step later, when
 * loadWalFile's OnStart finds the re-created head empty (wal.go:124-131)
 * — so an EMPTY head, which would re-arm the one-time SQLite carry
 * (`nodus_cmt_wal_carry_sqlite`), is never installed. A failure before
 * the rename removes `tmp` and leaves `dst` untouched; a failed directory
 * fsync AFTER the rename is CMT_FAULT with the complete head left in
 * place (removing it would leave an absent head — the carry again). */
static int wal_repair_file(const char *src, const char *dst, const char *tmp,
                           const char *dir, cmt_now_fn now, void *now_ctx)
{
    nodus_cmt_wal_t         *in;
    cmt_timed_wal_message_t *msg;
    int                      out = -1;
    int                      rc = CMT_OK;
    int                      kept = 0;
    bool                     renamed = false;

    in = (nodus_cmt_wal_t *)calloc(1, sizeof(*in));
    msg = (cmt_timed_wal_message_t *)malloc(sizeof(*msg));
    if (!in || !msg) {
        free(in);
        free(msg);
        return CMT_FAULT;
    }
    if (nodus_cmt_wal_open(in, src, now, now_ctx) != CMT_OK) {     /* :2622-2626 */
        free(in);
        free(msg);
        return CMT_FAULT;
    }
    /* :2628-2632 os.Create(dst) → HARDENING: a fresh temp file, not dst */
    if (unlink(tmp) != 0 && errno != ENOENT) {
        QGP_LOG_ERROR(LOG_TAG, "repair: remove stale %s: %s", tmp,
                      strerror(errno));
        nodus_cmt_wal_close(in);
        free(in);
        free(msg);
        return CMT_FAULT;
    }
    do {
        /* 0600, not the reference's os.Create 0666: this file is renamed
         * over the head, which autofile creates 0600 (ORCHESTRATOR). */
        out = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    } while (out < 0 && errno == EINTR);
    if (out < 0) {
        QGP_LOG_ERROR(LOG_TAG, "repair: create %s: %s", tmp, strerror(errno));
        nodus_cmt_wal_close(in);
        free(in);
        free(msg);
        return CMT_FAULT;
    }
    for (;;) {                                           /* :2640-2651 */
        bool   eof = false;
        size_t len = 0;

        if (nodus_cmt_wal_read_next(in, msg, &eof) != CMT_OK || eof) {
            break;                                       /* :2642-2644 */
        }
        /* :2646-2650 enc.Encode(msg) — the record's own Time is kept */
        if (wal_frame(in, msg, &len) != CMT_OK ||
            wal_write_all(out, in->enc_buf, len) != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "repair: failed to encode msg");
            rc = CMT_FAULT;
            break;
        }
        kept++;
    }
    if (rc == CMT_OK && kept == 0) {
        /* HARDENING: never an empty head (see above) */
        size_t len = 0;

        memset(msg, 0, sizeof(*msg));
        msg->msg.kind = CMT_PB_WAL_END_HEIGHT;
        msg->msg.u.end_height.height = 0;                /* wal.go:129 */
        if (now(now_ctx, &msg->time) != CMT_OK ||
            wal_frame(in, msg, &len) != CMT_OK ||
            wal_write_all(out, in->enc_buf, len) != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "repair: failed to write "
                          "EndHeight{0} into the empty repaired head");
            rc = CMT_FAULT;
        }
    }
    if (rc == CMT_OK && fsync(out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "repair: fsync %s: %s", tmp, strerror(errno));
        rc = CMT_FAULT;
    }
    if (close(out) != 0 && rc == CMT_OK) {               /* :2632 defer */
        QGP_LOG_ERROR(LOG_TAG, "repair: close %s: %s", tmp, strerror(errno));
        rc = CMT_FAULT;
    }
    out = -1;
    if (rc == CMT_OK) {
        if (rename(tmp, dst) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "repair: rename %s -> %s: %s", tmp, dst,
                          strerror(errno));
            rc = CMT_FAULT;
        } else {
            renamed = true;
        }
    }
    if (renamed && nodus_cmt_fsync_dir(dir) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "repair: the rename onto %s is not durable; "
                      "the repaired head stays in place", dst);
        rc = CMT_FAULT;
    }
    if (!renamed) {
        (void)unlink(tmp);
    }
    nodus_cmt_wal_close(in);                             /* :2626 defer */
    free(in);
    free(msg);
    if (rc == CMT_OK) {
        QGP_LOG_INFO(LOG_TAG, "repair: %d records kept from %s", kept, src);
    }
    return rc;
}

int nodus_cmt_wal_repair(nodus_cmt_wal_t *w)
{
    char        path[NODUS_CMT_AUTOFILE_PATH_MAX];
    char        corrupted[NODUS_CMT_AUTOFILE_PATH_MAX + 16];
    char        dir[NODUS_CMT_AUTOFILE_PATH_MAX];
    char        tmp[NODUS_CMT_AUTOFILE_PATH_MAX +
                    sizeof(NODUS_CMT_WAL_REPAIR_TMP_NAME)];
    const char *slash;
    const char *base;
    cmt_now_fn  now;
    void       *now_ctx;
    int         n;

    if (!w || !w->path[0] || !w->now) {
        return CMT_FAULT;
    }
    memcpy(path, w->path, sizeof(path));
    now = w->now;
    now_ctx = w->now_ctx;
    n = snprintf(corrupted, sizeof(corrupted), "%s%s", path,
                 NODUS_CMT_WAL_CORRUPTED_SUFFIX);        /* state.go:366 */
    if (n < 0 || (size_t)n >= sizeof(corrupted) ||
        (size_t)n >= NODUS_CMT_AUTOFILE_PATH_MAX) {
        return CMT_FAULT;
    }
    /* HARDENING 1(b): the temp file beside the head. Its name must not
     * start with the head's base name, or readGroupInfo's prefix match
     * (group.go:380) would count it into the group. */
    slash = strrchr(path, '/');
    if (!slash) {
        memcpy(dir, ".", 2);
        base = path;
    } else if (slash == path) {
        memcpy(dir, "/", 2);
        base = slash + 1;
    } else {
        memcpy(dir, path, (size_t)(slash - path));
        dir[slash - path] = '\0';
        base = slash + 1;
    }
    if (strncmp(NODUS_CMT_WAL_REPAIR_TMP_NAME, base, strlen(base)) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "repair: the temp name %s would match the "
                      "WAL head's prefix %s", NODUS_CMT_WAL_REPAIR_TMP_NAME,
                      base);
        return CMT_FAULT;
    }
    n = snprintf(tmp, sizeof(tmp), "%s/%s", dir, NODUS_CMT_WAL_REPAIR_TMP_NAME);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        return CMT_FAULT;
    }

    /* :359-361 cs.wal.Stop() — ErrNotStarted on a WAL never started */
    if (!w->started) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "repair: the WAL is not started");
        return CMT_FAULT;
    }
    nodus_cmt_wal_close(w);

    /* :366-369 — made, and (HARDENING 1(b)) durable with its directory
     * entry, before anything is rewritten */
    if (wal_copy_file(path, corrupted) != CMT_OK ||
        nodus_cmt_fsync_dir(dir) != CMT_OK) {
        return CMT_FAULT;
    }
    QGP_LOG_DEBUG(LOG_TAG, "backed up WAL file %s -> %s", path, corrupted);

    /* :374-377 — the WAL file is replaced (HARDENING 1(b): temp + rename) */
    if (wal_repair_file(corrupted, path, tmp, dir, now, now_ctx) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "the WAL repair failed");
        return CMT_FAULT;
    }
    QGP_LOG_INFO(LOG_TAG, "%s", "successful WAL repair");

    /* :382-384 loadWalFile → OpenWAL: NewWAL + Start (state.go:452-467) */
    if (nodus_cmt_wal_open(w, path, now, now_ctx) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "failed to load state WAL");
        return CMT_FAULT;
    }
    if (nodus_cmt_wal_start(w) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "failed to start WAL");
        nodus_cmt_wal_close(w);
        return CMT_FAULT;
    }
    return CMT_OK;
}

/* ══ the one-time carry-over from the SQLite-era WAL ════════════════════
 *
 * ⚠ NOT GROUNDED — the reference never migrates WAL storage (consensus/
 * wal.go and libs/autofile have no such step). Decision
 * 2026-09-26-cmt-wal-file-group.md item 6, AMENDED 2026-09-27 (operator
 * "1 aktarma kodu", red-team R5 F1). Contract: the header. The old row
 * format is read from nodus 0.19.80 (d123b7e6) nodus_witness_cmt_wal.c,
 * the table from nodus_witness_v2_schema.c (S14 `cmt_wal`). */

static const char SQL_CARRY_HAS_TABLE[] =
    "SELECT COUNT(*) FROM sqlite_master "
    "WHERE type = 'table' AND name = 'cmt_wal'";
/* rows of the protocol, and the seq of its latest EndHeight row */
static const char SQL_CARRY_SUMMARY[] =
    "SELECT COUNT(*), MAX(CASE WHEN kind = 4 THEN seq END) "
    "FROM cmt_wal WHERE protocol_id = ?1";
/* the tail, in append (seq) order; height only breaks a tie that the
 * old writer's monotonic seq never produces (checked below) */
static const char SQL_CARRY_TAIL[] =
    "SELECT height, seq, kind, bytes FROM cmt_wal "
    "WHERE protocol_id = ?1 AND seq >= ?2 ORDER BY seq ASC, height ASC";

/* The row's `height` column as the old writer derived it — the old
 * `nodus_cmt_wal_message_height` (d123b7e6 nodus_witness_cmt_wal.c:95-
 * 133), kept here only so the carry can check a row's columns against
 * its payload exactly as the old reader did. */
static int carry_message_height(const cmt_wal_message_t *msg, int64_t *out)
{
    switch (msg->kind) {
    case CMT_PB_WAL_EVENT_DATA_ROUND_STATE:
        *out = msg->u.event_data_round_state.height;     /* events.go:94 */
        return CMT_OK;
    case CMT_PB_WAL_MSG_INFO: {
        const cmt_msg_t *m = &msg->u.msg_info.msg;

        switch (m->kind) {
        case CMT_PB_CONS_MSG_NEW_ROUND_STEP:
            *out = m->u.new_round_step.height;
            return CMT_OK;
        case CMT_PB_CONS_MSG_NEW_VALID_BLOCK:
            *out = m->u.new_valid_block.height;
            return CMT_OK;
        case CMT_PB_CONS_MSG_PROPOSAL:
            *out = m->u.proposal.proposal.height;
            return CMT_OK;
        case CMT_PB_CONS_MSG_PROPOSAL_POL:
            *out = m->u.proposal_pol.height;
            return CMT_OK;
        case CMT_PB_CONS_MSG_BLOCK_PART:
            *out = m->u.block_part.height;
            return CMT_OK;
        case CMT_PB_CONS_MSG_VOTE:
            *out = m->u.vote.has_vote ? m->u.vote.vote.height : 0;
            return CMT_OK;
        case CMT_PB_CONS_MSG_HAS_VOTE:
            *out = m->u.has_vote.height;
            return CMT_OK;
        case CMT_PB_CONS_MSG_VOTE_SET_MAJ23:
            *out = m->u.vote_set_maj23.height;
            return CMT_OK;
        case CMT_PB_CONS_MSG_VOTE_SET_BITS:
            *out = m->u.vote_set_bits.height;
            return CMT_OK;
        default:
            return CMT_REJECT;
        }
    }
    case CMT_PB_WAL_TIMEOUT_INFO:
        *out = msg->u.timeout_info.height;               /* state.go:56 */
        return CMT_OK;
    case CMT_PB_WAL_END_HEIGHT:
        *out = msg->u.end_height.height;                 /* wal.go:43   */
        return CMT_OK;
    default:
        return CMT_REJECT;
    }
}

/* The old reader's `wal_decode_row` (d123b7e6 nodus_witness_cmt_wal.c:
 * 455-506), check for check. On CMT_OK `*out_p`/`*out_plen` name P
 * inside `blob`. Every failure is logged with the row's seq and height
 * and is CMT_FAULT (D-15 rev 5: stop, never skip). */
static int carry_check_row(int64_t row_height, int64_t row_seq, int row_kind,
                           const uint8_t *blob, size_t blob_len,
                           cmt_timed_wal_message_t *tw, cmt_pb_arena_t *arena,
                           const uint8_t **out_p, size_t *out_plen)
{
    uint8_t        want[NODUS_CMT_WAL_SQLITE_DIGEST_LEN];
    const uint8_t *p;
    size_t         plen;
    int64_t        h = 0;
    int            rc;

    if (!blob || blob_len < NODUS_CMT_WAL_SQLITE_DIGEST_LEN) {
        QGP_LOG_ERROR(LOG_TAG, "carry: cmt_wal row seq %lld height %lld is "
                      "shorter than its digest (%zu bytes)", (long long)row_seq,
                      (long long)row_height, blob_len);
        return CMT_FAULT;
    }
    p = blob + NODUS_CMT_WAL_SQLITE_DIGEST_LEN;
    plen = blob_len - NODUS_CMT_WAL_SQLITE_DIGEST_LEN;
    if (plen > (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES) {     /* wal.go:385-390 */
        QGP_LOG_ERROR(LOG_TAG, "carry: cmt_wal row seq %lld height %lld: "
                      "length %zu exceeded maximum possible value of %d "
                      "bytes", (long long)row_seq, (long long)row_height,
                      plen, (int)CMT_WAL_MAX_MSG_SIZE_BYTES);
        return CMT_FAULT;
    }
    if (qgp_sha3_512(p, plen, want) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "%s", "carry: SHA3-512 backend failed");
        return CMT_FAULT;
    }
    if (memcmp(want, blob, NODUS_CMT_WAL_SQLITE_DIGEST_LEN) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "carry: cmt_wal row seq %lld height %lld: "
                      "digest mismatch", (long long)row_seq,
                      (long long)row_height);
        return CMT_FAULT;
    }
    if (row_kind < (int)CMT_PB_WAL_EVENT_DATA_ROUND_STATE ||
        row_kind > (int)CMT_PB_WAL_END_HEIGHT) {
        QGP_LOG_ERROR(LOG_TAG, "carry: cmt_wal row seq %lld height %lld: "
                      "kind %d out of range", (long long)row_seq,
                      (long long)row_height, row_kind);
        return CMT_FAULT;
    }
    arena->used = 0;
    rc = cmt_timed_wal_message_decode(p, plen, tw, arena);
    if (rc != CMT_OK) {                                  /* wal.go:404-413 */
        QGP_LOG_ERROR(LOG_TAG, "carry: cmt_wal row seq %lld height %lld "
                      "does not decode (rc %d)", (long long)row_seq,
                      (long long)row_height, rc);
        return CMT_FAULT;
    }
    if ((int)tw->msg.kind != row_kind ||
        carry_message_height(&tw->msg, &h) != CMT_OK || h != row_height) {
        QGP_LOG_ERROR(LOG_TAG, "carry: cmt_wal row seq %lld height %lld: "
                      "columns disagree with its payload",
                      (long long)row_seq, (long long)row_height);
        return CMT_FAULT;
    }
    /* Decision 2026-09-27-p2p-fix-2.md item 1: the file reader's check,
     * the same way (wal_decode above — msgs.go:232-234 inside wal.go:410's
     * WALFromProto). A carried MsgInfo that fails ValidateBasic would be a
     * DataCorruptionError on the first replay, and that replay's repair
     * would cut the carried tail at it; so it is refused here, as a bad
     * row, before anything is written. */
    if (tw->msg.kind == CMT_PB_WAL_MSG_INFO) {
        rc = cmt_msg_validate_basic(&tw->msg.u.msg_info.msg);
        if (rc != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "carry: cmt_wal row seq %lld height %lld: "
                          "its message fails ValidateBasic (kind %d, rc %d)",
                          (long long)row_seq, (long long)row_height,
                          (int)tw->msg.u.msg_info.msg.kind, rc);
            return CMT_FAULT;
        }
    }
    *out_p = p;
    *out_plen = plen;
    return CMT_OK;
}

/* One-int answer of a prepared single-row query; `*out_null` is set when
 * column `col` is NULL. */
static int carry_query_int64(sqlite3 *db, const char *sql, bool bind_protocol,
                             int col, int64_t *out, bool *out_null)
{
    sqlite3_stmt *st = NULL;
    int           rc;

    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "carry: prepare failed (%s): %s", sql,
                      sqlite3_errmsg(db));
        return CMT_FAULT;
    }
    if (bind_protocol) {
        sqlite3_bind_int64(st, 1, (sqlite3_int64)NODUS_CMT_WAL_SQLITE_PROTOCOL_ID);
    }
    rc = sqlite3_step(st);
    if (rc != SQLITE_ROW) {
        QGP_LOG_ERROR(LOG_TAG, "carry: query failed (%s): %s", sql,
                      sqlite3_errmsg(db));
        sqlite3_finalize(st);
        return CMT_FAULT;
    }
    if (out_null) {
        *out_null = (sqlite3_column_type(st, col) == SQLITE_NULL);
    }
    *out = (int64_t)sqlite3_column_int64(st, col);
    sqlite3_finalize(st);
    return CMT_OK;
}

int nodus_cmt_wal_carry_sqlite(sqlite3 *db, const char *wal_file,
                               size_t *out_rows)
{
    char                     dir[NODUS_CMT_AUTOFILE_PATH_MAX];
    char                     tmp[NODUS_CMT_AUTOFILE_PATH_MAX +
                                 sizeof(NODUS_CMT_WAL_CARRY_TMP_NAME)];
    const char              *slash;
    nodus_cmt_group_t        probe;
    nodus_cmt_group_info_t   gi;
    struct stat              st;
    nodus_cmt_crc32_table_t  tab;
    sqlite3_stmt            *tail = NULL;
    cmt_timed_wal_message_t *tw = NULL;
    cmt_pb_arena_t           arena = { NULL, 0, 0 };
    uint8_t                 *frame = NULL;
    int64_t                  n_table = 0, n_rows = 0, end_seq = 0;
    int64_t                  end_height = -1, first_h = 0, last_h = 0;
    int64_t                  prev_seq = -1;
    bool                     end_null = true;
    bool                     renamed = false;
    size_t                   carried = 0;
    size_t                   pl;
    int                      fd = -1;
    int                      n;
    int                      rc = CMT_FAULT;
    int                      src;

    if (out_rows) {
        *out_rows = 0;
    }
    if (!db || !wal_file || !wal_file[0]) {
        return CMT_FAULT;
    }
    pl = strlen(wal_file);
    if (pl >= NODUS_CMT_AUTOFILE_PATH_MAX) {
        return CMT_FAULT;
    }

    /* the head's directory — ensured exactly as NewWAL does it
     * (wal.go:92, `nodus_cmt_wal_open` above) */
    slash = strrchr(wal_file, '/');
    if (!slash) {
        memcpy(dir, ".", 2);
    } else if (slash == wal_file) {
        memcpy(dir, "/", 2);
    } else {
        size_t dl = (size_t)(slash - wal_file);

        memcpy(dir, wal_file, dl);
        dir[dl] = '\0';
        if (wal_ensure_dir(dir, 0700) != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "%s", "carry: failed to ensure WAL "
                          "directory is in place");
            return CMT_FAULT;
        }
    }
    n = snprintf(tmp, sizeof(tmp), "%s/%s", dir, NODUS_CMT_WAL_CARRY_TMP_NAME);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        return CMT_FAULT;
    }

    /* (1) the head: absent or empty, else there is a file WAL already */
    if (stat(wal_file, &st) == 0) {
        if (st.st_size != 0) {
            QGP_LOG_DEBUG(LOG_TAG, "carry: %s holds %lld bytes — nothing to "
                          "carry", wal_file, (long long)st.st_size);
            return CMT_OK;
        }
    } else if (errno != ENOENT) {
        QGP_LOG_ERROR(LOG_TAG, "carry: stat %s: %s", wal_file,
                      strerror(errno));
        return CMT_FAULT;
    }

    /* (2) no rotated file: `readGroupInfo` over the head's name reads
     * only `head.path` (nodus_cmt_group_read_info); min = max = 0 exactly
     * when no `<head>.NNN` exists (group.go:401-409). */
    memset(&probe, 0, sizeof(probe));
    memcpy(probe.head.path, wal_file, pl + 1);
    probe.head.fd = -1;
    if (nodus_cmt_group_read_info(&probe, &gi) != CMT_OK) {
        QGP_LOG_ERROR(LOG_TAG, "carry: cannot read the WAL group of %s",
                      wal_file);
        return CMT_FAULT;
    }
    if (gi.min_index != 0 || gi.max_index != 0) {
        QGP_LOG_DEBUG(LOG_TAG, "carry: %s has rotated files (%d..%d) — "
                      "nothing to carry", wal_file, gi.min_index,
                      gi.max_index);
        return CMT_OK;
    }

    /* (3) the table, (4) its rows. An absent table is a database that
     * never ran the SQLite-era WAL: nothing to carry, not an error. */
    if (carry_query_int64(db, SQL_CARRY_HAS_TABLE, false, 0, &n_table,
                          NULL) != CMT_OK) {
        return CMT_FAULT;
    }
    if (n_table == 0) {
        return CMT_OK;
    }
    if (carry_query_int64(db, SQL_CARRY_SUMMARY, true, 0, &n_rows,
                          NULL) != CMT_OK ||
        carry_query_int64(db, SQL_CARRY_SUMMARY, true, 1, &end_seq,
                          &end_null) != CMT_OK) {
        return CMT_FAULT;
    }
    if (n_rows == 0) {
        return CMT_OK;
    }
    if (end_null) {
        /* unreachable from the old writer: its OnStart seeded
         * EndHeight{0} into an empty table (d123b7e6
         * nodus_witness_cmt_wal.c:292-302) and nothing deleted rows */
        QGP_LOG_ERROR(LOG_TAG, "carry: cmt_wal holds %lld rows and no "
                      "EndHeight row — refusing to start; the rows are "
                      "untouched, recovery is manual", (long long)n_rows);
        return CMT_FAULT;
    }

    tw = (cmt_timed_wal_message_t *)malloc(sizeof(*tw));
    frame = (uint8_t *)malloc(NODUS_CMT_WAL_RECORD_HEADER_LEN +
                              (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES);
    arena.cap = (size_t)CMT_WAL_MAX_MSG_SIZE_BYTES;
    arena.buf = (uint8_t *)malloc(arena.cap);
    if (!tw || !frame || !arena.buf) {
        goto out;
    }
    nodus_cmt_crc32_make_table(NODUS_CMT_CRC32C_POLY, tab); /* replay.go:20 */

    /* a temp file left by an attempt that crashed before its rename */
    if (unlink(tmp) != 0 && errno != ENOENT) {
        QGP_LOG_ERROR(LOG_TAG, "carry: remove stale %s: %s", tmp,
                      strerror(errno));
        goto out;
    }
    do {
        fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0) {
        QGP_LOG_ERROR(LOG_TAG, "carry: create %s: %s", tmp, strerror(errno));
        goto out;
    }

    if (sqlite3_prepare_v2(db, SQL_CARRY_TAIL, -1, &tail, NULL) != SQLITE_OK) {
        QGP_LOG_ERROR(LOG_TAG, "carry: prepare failed: %s", sqlite3_errmsg(db));
        goto out;
    }
    sqlite3_bind_int64(tail, 1, (sqlite3_int64)NODUS_CMT_WAL_SQLITE_PROTOCOL_ID);
    sqlite3_bind_int64(tail, 2, (sqlite3_int64)end_seq);
    while ((src = sqlite3_step(tail)) == SQLITE_ROW) {
        int64_t        row_h = (int64_t)sqlite3_column_int64(tail, 0);
        int64_t        row_seq = (int64_t)sqlite3_column_int64(tail, 1);
        int            row_kind = sqlite3_column_int(tail, 2);
        const uint8_t *blob = (const uint8_t *)sqlite3_column_blob(tail, 3);
        size_t         blob_len = (size_t)sqlite3_column_bytes(tail, 3);
        const uint8_t *p = NULL;
        size_t         plen = 0;

        if (row_seq <= prev_seq) {
            QGP_LOG_ERROR(LOG_TAG, "carry: cmt_wal row seq %lld height %lld "
                          "does not follow seq %lld", (long long)row_seq,
                          (long long)row_h, (long long)prev_seq);
            goto out;
        }
        if (carry_check_row(row_h, row_seq, row_kind, blob, blob_len, tw,
                            &arena, &p, &plen) != CMT_OK) {
            goto out;
        }
        if (carried == 0) {
            /* the query starts AT the latest EndHeight row */
            if (tw->msg.kind != CMT_PB_WAL_END_HEIGHT || row_seq != end_seq) {
                QGP_LOG_ERROR(LOG_TAG, "carry: the tail does not start at "
                              "the EndHeight row seq %lld", (long long)end_seq);
                goto out;
            }
            end_height = row_h;
            first_h = row_h;
        }
        last_h = row_h;
        prev_seq = row_seq;

        /* wal.go:316-326 — crc32c(P) BE ‖ len(P) BE ‖ P, P unchanged */
        put_be32(frame, nodus_cmt_crc32_update(0, tab, p, plen));
        put_be32(frame + 4, (uint32_t)plen);
        memcpy(frame + NODUS_CMT_WAL_RECORD_HEADER_LEN, p, plen);
        if (wal_write_all(fd, frame, NODUS_CMT_WAL_RECORD_HEADER_LEN + plen)
            != CMT_OK) {
            QGP_LOG_ERROR(LOG_TAG, "carry: write %s: %s", tmp, strerror(errno));
            goto out;
        }
        carried++;
    }
    if (src != SQLITE_DONE) {
        QGP_LOG_ERROR(LOG_TAG, "carry: reading cmt_wal failed: %s",
                      sqlite3_errmsg(db));
        goto out;
    }
    if (carried == 0) {
        QGP_LOG_ERROR(LOG_TAG, "carry: the EndHeight row seq %lld vanished "
                      "between two reads", (long long)end_seq);
        goto out;
    }

    /* durable, then visible under the head's name, then the rename
     * itself durable */
    if (fsync(fd) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "carry: fsync %s: %s", tmp, strerror(errno));
        goto out;
    }
    n = close(fd);
    fd = -1;
    if (n != 0) {
        QGP_LOG_ERROR(LOG_TAG, "carry: close %s: %s", tmp, strerror(errno));
        goto out;
    }
    if (rename(tmp, wal_file) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "carry: rename %s -> %s: %s", tmp, wal_file,
                      strerror(errno));
        goto out;
    }
    renamed = true;
    if (nodus_cmt_fsync_dir(dir) != CMT_OK) {
        /* the head is in place but its name may not survive a power cut;
         * refuse to start rather than sign on a WAL that may vanish —
         * and remove it, so the next start carries again */
        goto out;
    }
    QGP_LOG_INFO(LOG_TAG, "consensus WAL carry-over: %zu rows from the "
                 "SQLite cmt_wal table (EndHeight %lld, heights %lld..%lld) "
                 "written to %s; the rows are left in place", carried,
                 (long long)end_height, (long long)first_h, (long long)last_h,
                 wal_file);
    if (out_rows) {
        *out_rows = carried;
    }
    rc = CMT_OK;
out:
    if (tail) {
        sqlite3_finalize(tail);
    }
    if (fd >= 0) {
        (void)close(fd);
    }
    if (rc != CMT_OK) {
        (void)unlink(tmp);
        if (renamed) {
            (void)unlink(wal_file);
        }
    }
    free(tw);
    free(frame);
    free(arena.buf);
    return rc;
}
