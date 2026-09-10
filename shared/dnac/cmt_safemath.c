/**
 * @file shared/dnac/cmt_safemath.c
 * @brief cometbft @709fd12b `libs/math/safemath.go` in C — see cmt_safemath.h.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include "dnac/cmt_safemath.h"

/* cometbft@709fd12b libs/math/safemath.go:14-21 — SafeAddInt32() */
int cmt_safe_add_int32(int32_t a, int32_t b, int32_t *out)
{
    int64_t wa = (int64_t)a;
    int64_t wb = (int64_t)b;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (wb > 0 && wa > (int64_t)INT32_MAX - wb) {    /* :15-16 */
        return CMT_REJECT;
    }
    if (wb < 0 && wa < (int64_t)INT32_MIN - wb) {    /* :17-18 */
        return CMT_REJECT;
    }
    *out = (int32_t)(wa + wb);                       /* :20 */
    return CMT_OK;
}

/* cometbft@709fd12b libs/math/safemath.go:25-32 — SafeSubInt32() */
int cmt_safe_sub_int32(int32_t a, int32_t b, int32_t *out)
{
    int64_t wa = (int64_t)a;
    int64_t wb = (int64_t)b;

    if (out == NULL) {
        return CMT_FAULT;
    }
    if (wb > 0 && wa < (int64_t)INT32_MIN + wb) {    /* :26-27 */
        return CMT_REJECT;
    }
    if (wb < 0 && wa > (int64_t)INT32_MAX + wb) {    /* :28-29 */
        return CMT_REJECT;
    }
    *out = (int32_t)(wa - wb);                       /* :31 */
    return CMT_OK;
}

/* cometbft@709fd12b libs/math/safemath.go:36-43 — SafeConvertInt32() */
int cmt_safe_convert_int32(int64_t a, int32_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (a > (int64_t)INT32_MAX) {                    /* :37-38 */
        return CMT_REJECT;
    }
    if (a < (int64_t)INT32_MIN) {                    /* :39-40 */
        return CMT_REJECT;
    }
    *out = (int32_t)a;                               /* :42 */
    return CMT_OK;
}

/* cometbft@709fd12b libs/math/safemath.go:47-54 — SafeConvertUint8() */
int cmt_safe_convert_uint8(int64_t a, uint8_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (a > (int64_t)UINT8_MAX) {                    /* :48-49 */
        return CMT_REJECT;
    }
    if (a < 0) {                                     /* :50-51 */
        return CMT_REJECT;
    }
    *out = (uint8_t)a;                               /* :53 */
    return CMT_OK;
}

/* cometbft@709fd12b libs/math/safemath.go:58-65 — SafeConvertInt8() */
int cmt_safe_convert_int8(int64_t a, int8_t *out)
{
    if (out == NULL) {
        return CMT_FAULT;
    }
    if (a > (int64_t)INT8_MAX) {                     /* :59-60 */
        return CMT_REJECT;
    }
    if (a < (int64_t)INT8_MIN) {                     /* :61-62 */
        return CMT_REJECT;
    }
    *out = (int8_t)a;                                /* :64 */
    return CMT_OK;
}
