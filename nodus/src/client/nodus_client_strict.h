/**
 * @file nodus/src/client/nodus_client_strict.h
 * @brief Strict DHT reads: a value the node SENT but the client could not
 *        decode is reported, never folded into "not found".
 *
 * Why (Nodus Connect web design rev 5 §6.4 F1, docs/plans/2026-09-24-web-
 * connect-design.md): the tier-2 decoder ignores nodus_value_deserialize's
 * return (nodus_tier2.c "val (result single)" and "vals (result multi)"
 * branches), so a malformed "val" leaves msg->value == NULL and
 * nodus_client_get answers NODUS_ERR_NOT_FOUND — the same answer as "the
 * node holds nothing". A reader that treats NOT_FOUND as "absent" may then
 * create a record that exists (thin-core decision 2026-09-30-nodus-connect-
 * thin-core.md, S3: "okuyamadım" -> never write). For get_all the decoder
 * drops each bad entry silently, so a partial answer looks complete.
 *
 * WHAT CHANGES: nothing for existing callers. nodus_client_get and
 * nodus_client_get_all keep their behaviour; they and the strict variants
 * share one implementation in nodus_client.c. The strict variants re-read
 * the raw reply the client already keeps (nodus_pending_t.raw_response) and
 * compare what the node sent with what decoded. The decoder
 * (nodus_t2_decode) and every server path are untouched: the server decodes
 * with nodus_t2_decode directly and never calls these functions.
 *
 * Callers today: the Nodus Connect thin core (web-wallet/connect/nc_read.c).
 */

#ifndef NODUS_CLIENT_STRICT_H
#define NODUS_CLIENT_STRICT_H

#include "nodus/nodus.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** What a raw tier-2 reply carries in its "r" map (the result map). */
typedef struct {
    bool   has_r;          /* the frame has an "r" map                      */
    bool   has_val;        /* "r" has a "val" key (single-value result)     */
    bool   val_is_bstr;    /* ... and it is a byte string                   */
    bool   has_vals;       /* "r" has a "vals" key that is an array         */
    size_t vals_total;     /* items in that array (any CBOR type)           */
    size_t vals_bstr;      /* ... of which byte strings                     */
} nodus_reply_value_shape_t;

/**
 * Walk a raw tier-2 reply (a whole frame payload, as nodus_t2_decode takes
 * it) and report whether its "r" map carries "val" / "vals". Pure function
 * over the bytes; allocates nothing.
 *
 * @return 0 if the frame is a CBOR map (shape filled; has_r false when there
 *         is no "r" map), -1 if the bytes are not a CBOR map or the walk hits
 *         a decode error.
 */
int nodus_client_reply_value_shape(const uint8_t *raw, size_t raw_len,
                                   nodus_reply_value_shape_t *out);

/**
 * GET, strict. Same request and ownership rules as nodus_client_get, except:
 *   - the reply carried a "val" (any CBOR type) that did not decode
 *     -> NODUS_ERR_PROTOCOL_ERROR (never NODUS_ERR_NOT_FOUND);
 *   - the raw reply could not be kept (allocation failure) and no value
 *     decoded -> NODUS_ERR_PROTOCOL_ERROR (the absence cannot be shown).
 * NODUS_ERR_NOT_FOUND therefore means: the node answered, and its answer
 * carried no value at all. It does NOT mean the key is absent from the DHT
 * (design §2.1: the node answers "empty" on an incomplete lookup too).
 */
int nodus_client_get_strict(nodus_client_t *client,
                            const nodus_key_t *key,
                            nodus_value_t **val_out);

/**
 * GET_ALL, strict. Same as nodus_client_get_all (the decoded values are
 * returned, caller frees each with nodus_value_free and the array with
 * free), plus `*undecodable_out` = how many items the node sent that did not
 * decode (a non-byte-string item, a value nodus_value_deserialize refused,
 * or an item beyond the decoder's NODUS_MAX_WIRE_VALUES cap). When the raw
 * reply could not be kept, the call returns NODUS_ERR_PROTOCOL_ERROR and no
 * values (the count cannot be shown).
 *
 * A get_all answer is never proof that the set is complete (design §6.4 F5:
 * the node may answer from local storage only, or with what a timed-out
 * forwarding batch collected).
 */
int nodus_client_get_all_strict(nodus_client_t *client,
                                const nodus_key_t *key,
                                nodus_value_t ***vals_out,
                                size_t *count_out,
                                size_t *undecodable_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CLIENT_STRICT_H */
