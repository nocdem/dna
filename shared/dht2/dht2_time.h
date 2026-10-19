/**
 * @file shared/dht2/dht2_time.h
 * @brief DHT v2 — the `Validity` text of a record ↔ chain-time seconds.
 *
 * Design rev 5 §3.1 "Data map keys" and §13 row 6: `Validity` is exactly
 * the 20 ASCII bytes `YYYY-MM-DDTHH:MM:SSZ` of a chain time in whole
 * seconds — proleptic Gregorian UTC, years 1970-9999, no fraction,
 * seconds 00-59 (no leap second), converted to seconds since
 * 1970-01-01T00:00:00Z; any other byte form is `bad-encoding`.
 *
 * Named deviation (design §13 row 21): a NARROWING of boxo's RFC3339Nano
 * (boxo v0.43.0 util/time.go: TimeFormatIpfs = time.RFC3339Nano), which
 * prints exactly this form for a UTC time with a zero fraction — so every
 * text produced here is one boxo also produces; boxo accepts more.
 *
 * Pure arithmetic: no clock, no locale, no libc time functions (no timegm
 * / gmtime_r / strptime — this file is in the common source list and must
 * build on Windows). The multiplications that make the seconds value use
 * the tree's checked u64 arithmetic (dna_ck_*_u64, shared/dnac/res_meter.h
 * :190-194), per row 6.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef SHARED_DHT2_TIME_H
#define SHARED_DHT2_TIME_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 9999-12-31T23:59:59Z — the last second the 20-byte form can name. */
#define DHT2_VALIDITY_MAX_SECONDS 253402300799ull

/** Parse exactly `len` bytes. 0 with *out_seconds written, or -1 for ANY
 *  other byte form (wrong length, a non-digit, a lowercase 'T'/'Z', an
 *  offset, a fraction, a field out of range, a day the month does not
 *  have, a year outside 1970-9999). */
int dht2_validity_parse(const uint8_t *text, size_t len, uint64_t *out_seconds);

/** Format `seconds` (0 … DHT2_VALIDITY_MAX_SECONDS) as the 20 bytes
 *  (no NUL written). 0 / -1 (out of range or NULL). */
int dht2_validity_format(uint64_t seconds, uint8_t out[20]);

#ifdef __cplusplus
}
#endif

#endif /* SHARED_DHT2_TIME_H */
