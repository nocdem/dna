/**
 * @file shared/dht2/dht2_time.c
 * @brief DHT v2 — `Validity` text ↔ seconds. See dht2_time.h.
 *
 * The day count is the standard proleptic-Gregorian era arithmetic
 * (400-year era of 146,097 days; March-based year so the leap day is the
 * last day of the year). It is verified in test_dht2_codec.c against
 * fixed instants whose seconds were computed with GNU `date -u -d … +%s`
 * and by a full round trip at every month boundary.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dht2/dht2_time.h"
#include "dnac/res_meter.h"     /* dna_ck_add_u64 / dna_ck_mul_u64 */

#include <stdbool.h>

/* Days from 1970-01-01 to the civil date (y ≥ 1970, m 1-12, d 1-31
 * already validated). All terms are non-negative in this range. */
static uint64_t days_from_civil(uint64_t y, uint64_t m, uint64_t d)
{
    uint64_t era, yoe, doy, doe;

    if (m <= 2) {
        y -= 1;
    }
    era = y / 400;
    yoe = y - era * 400;                                     /* [0, 399] */
    doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;   /* [0, 365] */
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;             /* [0, 146096] */
    return era * 146097 + doe - 719468;                      /* 719468 = 1970-03-01 offset */
}

static void civil_from_days(uint64_t days, uint64_t *y, uint64_t *m,
                            uint64_t *d)
{
    uint64_t z   = days + 719468;
    uint64_t era = z / 146097;
    uint64_t doe = z - era * 146097;
    uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    uint64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    uint64_t mp  = (5 * doy + 2) / 153;

    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = (mp < 10) ? mp + 3 : mp - 9;
    *y = yoe + era * 400 + ((*m <= 2) ? 1 : 0);
}

static bool is_leap(uint64_t y)
{
    return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
}

static uint64_t days_in_month(uint64_t y, uint64_t m)
{
    static const uint8_t dim[12] = { 31, 28, 31, 30, 31, 30,
                                     31, 31, 30, 31, 30, 31 };

    if (m == 2 && is_leap(y)) {
        return 29;
    }
    return dim[m - 1];
}

static int digits(const uint8_t *p, size_t n, uint64_t *out)
{
    uint64_t v = 0;
    size_t   k;

    for (k = 0; k < n; k++) {
        if (p[k] < '0' || p[k] > '9') {
            return -1;
        }
        v = v * 10 + (uint64_t)(p[k] - '0');
    }
    *out = v;
    return 0;
}

int dht2_validity_parse(const uint8_t *text, size_t len, uint64_t *out_seconds)
{
    uint64_t y, mo, d, h, mi, s, days, acc, t;

    if (text == NULL || out_seconds == NULL || len != 20) {
        return -1;
    }
    /* YYYY-MM-DDTHH:MM:SSZ — positions 4, 7 '-', 10 'T', 13, 16 ':',
     * 19 'Z' (uppercase only; no offset, no fraction). */
    if (text[4] != '-' || text[7] != '-' || text[10] != 'T' ||
        text[13] != ':' || text[16] != ':' || text[19] != 'Z') {
        return -1;
    }
    if (digits(text + 0, 4, &y) != 0 || digits(text + 5, 2, &mo) != 0 ||
        digits(text + 8, 2, &d) != 0 || digits(text + 11, 2, &h) != 0 ||
        digits(text + 14, 2, &mi) != 0 || digits(text + 17, 2, &s) != 0) {
        return -1;
    }
    if (y < 1970 || y > 9999 || mo < 1 || mo > 12 || d < 1 ||
        d > days_in_month(y, mo) || h > 23 || mi > 59 || s > 59) {
        return -1;
    }
    days = days_from_civil(y, mo, d);

    /* seconds = days·86400 + h·3600 + mi·60 + s, checked (row 6). */
    if (dna_ck_mul_u64(days, 86400u, &acc) != 0 ||
        dna_ck_mul_u64(h, 3600u, &t) != 0 ||
        dna_ck_add_u64(acc, t, &acc) != 0 ||
        dna_ck_mul_u64(mi, 60u, &t) != 0 ||
        dna_ck_add_u64(acc, t, &acc) != 0 ||
        dna_ck_add_u64(acc, s, &acc) != 0) {
        return -1;
    }
    *out_seconds = acc;
    return 0;
}

static void put2(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)('0' + (v / 10) % 10);
    p[1] = (uint8_t)('0' + v % 10);
}

int dht2_validity_format(uint64_t seconds, uint8_t out[20])
{
    uint64_t days, rem, y, m, d;

    if (out == NULL || seconds > DHT2_VALIDITY_MAX_SECONDS) {
        return -1;
    }
    days = seconds / 86400u;
    rem  = seconds % 86400u;
    civil_from_days(days, &y, &m, &d);

    out[0] = (uint8_t)('0' + (y / 1000) % 10);
    out[1] = (uint8_t)('0' + (y / 100) % 10);
    out[2] = (uint8_t)('0' + (y / 10) % 10);
    out[3] = (uint8_t)('0' + y % 10);
    out[4] = '-';
    put2(out + 5, m);
    out[7] = '-';
    put2(out + 8, d);
    out[10] = 'T';
    put2(out + 11, rem / 3600u);
    out[13] = ':';
    put2(out + 14, (rem / 60u) % 60u);
    out[16] = ':';
    put2(out + 17, rem % 60u);
    out[19] = 'Z';
    return 0;
}
