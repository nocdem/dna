/**
 * @file shared/dnac/cmt_flowrate.c
 * @brief cometbft @709fd12b `libs/flowrate/flowrate.go` + `util.go` in C.
 *
 * Functions in the reference's order; each names its Go lines. Contract,
 * deviations (R-P2P-15 clock, R-P2P-16 blocking) and the determinism note
 * are in cmt_flowrate.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_flowrate.h"

#include <math.h>
#include <string.h>

#define NS_PER_SECOND (1000LL * 1000 * 1000)

/* ══ util.go ══════════════════════════════════════════════════════════ */

/* util.go:21-23 `clock()` = time.Now().Round(clockRate).Sub(czero). The
 * caller supplies the monotonic instant; Time.Round's rule is "half
 * rounds up" (Go src/time/time.go:1550-1554, lessThanHalf :808-810). The
 * czero anchor cancels (header, R-P2P-15). */
int64_t cmt_flowrate_clock(int64_t now_ns)
{
    int64_t r;

    if (now_ns < 0) {
        now_ns = 0;
    }
    r = now_ns % CMT_FLOWRATE_CLOCK_RATE_NS;
    if ((uint64_t)r + (uint64_t)r < (uint64_t)CMT_FLOWRATE_CLOCK_RATE_NS) {
        return now_ns - r;
    }
    return now_ns + (CMT_FLOWRATE_CLOCK_RATE_NS - r);
}

/* util.go:31-33 `clockRound(d)` = (d + clockRate>>1) / clockRate * clockRate. */
int64_t cmt_flowrate_clock_round(int64_t d)
{
    return (d + (CMT_FLOWRATE_CLOCK_RATE_NS >> 1)) / CMT_FLOWRATE_CLOCK_RATE_NS *
           CMT_FLOWRATE_CLOCK_RATE_NS;
}

/* util.go:36-41 `round(x)` — "non-negative values only". */
int64_t cmt_flowrate_round(double x)
{
    double ip;
    double frac = modf(x, &ip);

    if (frac >= 0.5) {
        return (int64_t)ceil(x);
    }
    return (int64_t)floor(x);
}

/* util.go:47-54 `percentOf(x, total)`. */
static uint32_t percent_of(double x, double total)
{
    int64_t p;

    if (x < 0 || total <= 0) {
        return 0;
    }
    p = cmt_flowrate_round(x / total * 1e5);
    if (p <= (int64_t)UINT32_MAX) {
        return (uint32_t)p;
    }
    return UINT32_MAX;
}

/* time.Duration.Seconds() (Go src/time/time.go:777-781). */
static double dur_seconds(int64_t d)
{
    int64_t sec  = d / NS_PER_SECOND;
    int64_t nsec = d % NS_PER_SECOND;

    return (double)sec + (double)nsec / 1e9;
}

/* ══ flowrate.go ══════════════════════════════════════════════════════ */

/* flowrate.go:250-255 `reset(sampleTime)`. */
static void fr_reset(cmt_flowrate_t *m, int64_t sample_time)
{
    m->bytes += m->s_bytes;
    m->samples++;
    m->s_bytes = 0;
    m->s_last = sample_time;
}

/* flowrate.go:222-247 `update(n)`. Returns the clock value it read, or 0
 * when inactive (the reference's zero `now`, :223-225). */
static int64_t fr_update(cmt_flowrate_t *m, int n, int64_t now_ns)
{
    int64_t now;
    int64_t s_time;

    if (!m->active) {                                          /* :223 */
        return 0;
    }
    now = cmt_flowrate_clock(now_ns);                          /* :226 */
    if (n > 0) {
        m->t_last = now;                                       /* :227 */
    }
    m->s_bytes += (int64_t)n;                                  /* :229 */
    s_time = now - m->s_last;
    if (s_time >= m->s_rate) {                                 /* :230 */
        double t = dur_seconds(s_time);                        /* :231 */

        m->r_sample = (double)m->s_bytes / t;                  /* :232 */
        if (m->r_sample > m->r_peak) {
            m->r_peak = m->r_sample;                           /* :233 */
        }
        if (m->samples > 0) {                                  /* :238 */
            double w = exp(-t / m->r_window);                  /* :239 */

            m->r_ema = m->r_sample + w * (m->r_ema - m->r_sample); /* :240 */
        } else {
            m->r_ema = m->r_sample;                            /* :242 */
        }
        fr_reset(m, now);                                      /* :244 */
    }
    return now;
}

/* flowrate.go:49-65 `New`. */
void cmt_flowrate_init(cmt_flowrate_t *m, int64_t sample_rate_ns,
                       int64_t window_size_ns, int64_t now_ns)
{
    int64_t now;

    if (m == NULL) {
        return;
    }
    sample_rate_ns = cmt_flowrate_clock_round(sample_rate_ns);  /* :50 */
    if (sample_rate_ns <= 0) {
        sample_rate_ns = CMT_FLOWRATE_DEFAULT_SAMPLE_NS;        /* :51 */
    }
    if (window_size_ns <= 0) {
        window_size_ns = CMT_FLOWRATE_DEFAULT_WINDOW_NS;        /* :54 */
    }
    now = cmt_flowrate_clock(now_ns);                           /* :56 */
    memset(m, 0, sizeof(*m));
    m->active   = true;                                         /* :58-63 */
    m->start    = now;
    m->r_window = dur_seconds(window_size_ns);
    m->s_last   = now;
    m->s_rate   = sample_rate_ns;
    m->t_last   = now;
}

/* flowrate.go:69-74 `Update`. */
int cmt_flowrate_update(cmt_flowrate_t *m, int n, int64_t now_ns)
{
    if (m == NULL) {
        return n;
    }
    (void)fr_update(m, n, now_ns);
    return n;
}

/* flowrate.go:77-82 `SetREMA`. */
void cmt_flowrate_set_rema(cmt_flowrate_t *m, double r_ema)
{
    if (m == NULL) {
        return;
    }
    m->r_ema = r_ema;
    m->samples++;
}

/* flowrate.go:93-103 `Done`. */
int64_t cmt_flowrate_done(cmt_flowrate_t *m, int64_t now_ns)
{
    int64_t now;

    if (m == NULL) {
        return 0;
    }
    now = fr_update(m, 0, now_ns);                             /* :95 */
    if (m->s_bytes > 0) {
        fr_reset(m, now);                                      /* :96 */
    }
    m->active = false;                                         /* :98 */
    m->t_last = 0;                                             /* :99 */
    return m->bytes;                                           /* :100 */
}

/* flowrate.go:128-164 `Status`. */
void cmt_flowrate_status(cmt_flowrate_t *m, int64_t now_ns,
                         cmt_flowrate_status_t *s)
{
    int64_t now;

    if (m == NULL || s == NULL) {
        return;
    }
    now = fr_update(m, 0, now_ns);                             /* :130 */
    memset(s, 0, sizeof(*s));
    s->active    = m->active;                                  /* :132 */
    s->start_ns  = m->start;                                   /* :133 */
    s->duration  = m->s_last - m->start;                       /* :134 */
    s->idle      = now - m->t_last;                            /* :135 */
    s->bytes     = m->bytes;                                   /* :136 */
    s->samples   = m->samples;                                 /* :137 */
    s->peak_rate = cmt_flowrate_round(m->r_peak);              /* :138 */
    s->bytes_rem = m->t_bytes - m->bytes;                      /* :139 */
    s->progress  = percent_of((double)m->bytes, (double)m->t_bytes); /* :140 */
    if (s->bytes_rem < 0) {
        s->bytes_rem = 0;                                      /* :142-144 */
    }
    if (s->duration > 0) {                                     /* :145 */
        double r_avg = (double)s->bytes / dur_seconds(s->duration);

        s->avg_rate = cmt_flowrate_round(r_avg);               /* :147 */
        if (s->active) {                                       /* :148 */
            s->inst_rate = cmt_flowrate_round(m->r_sample);    /* :149 */
            s->cur_rate  = cmt_flowrate_round(m->r_ema);       /* :150 */
            if (s->bytes_rem > 0) {                            /* :151 */
                double t_rate = 0.8 * m->r_ema + 0.2 * r_avg;  /* :152 */

                if (t_rate > 0) {
                    double ns = (double)s->bytes_rem / t_rate * 1e9; /* :153 */

                    if (ns > (double)CMT_FLOWRATE_TIME_REM_LIMIT_NS) {
                        ns = (double)CMT_FLOWRATE_TIME_REM_LIMIT_NS; /* :154-156 */
                    }
                    s->time_rem = cmt_flowrate_clock_round((int64_t)ns); /* :157 */
                }
            }
        }
    }
}

/* flowrate.go:177-206 `Limit`, with waitNextSample (:260-276) turned into
 * a returned retry instant (header, R-P2P-16). */
int cmt_flowrate_limit(cmt_flowrate_t *m, int want, int64_t rate, bool block,
                       int64_t now_ns, bool *would_block,
                       int64_t *retry_at_ns)
{
    int64_t limit;
    int64_t now;

    if (would_block != NULL) {
        *would_block = false;
    }
    if (want < 1 || rate < 1 || m == NULL) {                   /* :178-180 */
        return want;
    }

    limit = cmt_flowrate_round((double)rate * dur_seconds(m->s_rate)); /* :184 */
    if (limit <= 0) {
        limit = 1;                                             /* :185-187 */
    }

    now = fr_update(m, 0, now_ns);                             /* :190 */
    if (block && m->s_bytes >= limit && m->active) {           /* :191 */
        /* :260-270 waitNextSample: sleep d = current + sRate - now, at
         * least minWait. The next call's update(0) is the wake-up (:273). */
        int64_t d = m->s_last + m->s_rate - now;

        if (d < CMT_FLOWRATE_MIN_WAIT_NS) {
            d = CMT_FLOWRATE_MIN_WAIT_NS;
        }
        if (would_block != NULL) {
            *would_block = true;
        }
        if (retry_at_ns != NULL) {
            *retry_at_ns = now_ns + d;
        }
        return 0;
    }

    limit -= m->s_bytes;                                       /* :197 */
    if (limit > (int64_t)want || !m->active) {
        limit = (int64_t)want;                                 /* :198 */
    }
    if (limit < 0) {
        limit = 0;                                             /* :202-204 */
    }
    return (int)limit;
}

/* flowrate.go:210-217 `SetTransferSize`. */
void cmt_flowrate_set_transfer_size(cmt_flowrate_t *m, int64_t bytes)
{
    if (m == NULL) {
        return;
    }
    if (bytes < 0) {
        bytes = 0;
    }
    m->t_bytes = bytes;
}
