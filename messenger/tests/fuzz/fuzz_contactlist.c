/**
 * @file fuzz_contactlist.c
 * @brief libFuzzer harness: contact-list record (blob header, Seal, JSON).
 *
 * The blob parser (dht_contactlist.c:481-640, inside dht_contactlist_fetch)
 * and the JSON parser (deserialize_from_json, static, dht_contactlist.c:147)
 * sit in a file that also does DHT I/O, and NC-1 moves them in parallel, so
 * this target fuzzes the nearest exported entry point:
 *   dht_contactlist_fetch      dht_contactlist.c:447
 * with messenger/dht/client/dht_contactlist.c and messenger/dna_api.c
 * compiled in unchanged and the nodus_ops read replaced by fuzz_dht_stub.c.
 *
 * Input byte 0 selects the mode (low bit):
 *   0  raw:    bytes 1.. are the DHT value itself. Reaches the header parse
 *              (magic, version, timestamp, expiry, the two length fields) and
 *              the Seal decode; a random blob cannot pass the Seal decrypt,
 *              so the JSON parser is NOT reached in this mode. This is what
 *              a party who can serve or pre-store the value controls (web
 *              Connect design rev 5 §2.2 EXCLUSIVE freeze, §5 A4/A5).
 *   1  sealed: bytes 1.. are the JSON plaintext. The harness seals it with
 *              the local keys exactly as dht_contactlist_publish does
 *              (dna_encrypt_message_raw, self-encryption, signed by the own
 *              ML-DSA key), and wraps it in the header of a blob the REAL
 *              publisher produced at start-up. Reaches deserialize_from_json
 *              with arbitrary JSON. Only the list owner can produce this in
 *              reality (authorship check, dht_contactlist.c "Step 5"); the
 *              mode exists so the JSON parser gets memory-safety coverage.
 *
 * Blob layout used to re-wrap the sealed JSON is the one the parser reads
 * and the publisher writes (dht_contactlist.c:372-411): magic(4) version(1)
 * timestamp(8) expiry(8) enc_len(4, BE) enc(enc_len) sig_len(4, BE) sig.
 * Only enc_len and enc are replaced; everything else is the real
 * publisher's output.
 *
 * Throughput note: sealed mode signs (ML-DSA-87) and encapsulates (Kyber r3)
 * once per input, so it runs far slower than raw mode.
 *
 * FUZZ_CONTACTLIST_RAW_ONLY (set by build_wasm32.sh): json-c has no wasm32
 * build here, so that build has no real publisher (the template) and no JSON
 * parser. The mode byte is then ignored and every input runs in raw mode.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "dht/client/dht_contactlist.h"
#include "dna_api.h"
#include "crypto/utils/qgp_log.h"
#include "fuzz_keys.h"
#include "fuzz_dht_stub.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* magic(4) + version(1) + timestamp(8) + expiry(8) */
#define CL_HEADER_BYTES   21
#define CL_ENC_LEN_BYTES  4

static fuzz_identity_t *s_self;
static int              s_ready;

#ifndef FUZZ_CONTACTLIST_RAW_ONLY
static dna_context_t   *s_ctx;
static uint8_t         *s_template;       /* real publisher output */
static size_t           s_template_len;
static size_t           s_template_tail;  /* offset of sig_len in s_template */

static uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void init_template(void) {
    s_ctx = dna_context_new();
    if (!s_ctx) {
        abort();
    }

    /* One real publish, captured by the stub, gives the blob template */
    fuzz_identity_t *contact = calloc(1, sizeof(*contact));
    if (!contact || fuzz_identity_derive(contact, FUZZ_ID_CONTACT) != 0) {
        abort();
    }
    const char *contacts[1] = { contact->fp_hex };
    fuzz_dht_stub_reset();
    if (dht_contactlist_publish(s_self->fp_hex, contacts, 1, NULL,
                                s_self->kyber_pk, s_self->kyber_sk,
                                s_self->sign_pk, s_self->sign_sk, 0) != 0) {
        abort();
    }
    free(contact);

    size_t len = 0;
    const uint8_t *blob = fuzz_dht_stub_last_put(&len);
    if (!blob || len < CL_HEADER_BYTES + CL_ENC_LEN_BYTES) {
        abort();
    }
    uint32_t enc_len = rd_be32(blob + CL_HEADER_BYTES);
    size_t tail = CL_HEADER_BYTES + CL_ENC_LEN_BYTES + (size_t)enc_len;
    if (tail > len) {
        abort();
    }
    s_template = malloc(len);
    if (!s_template) {
        abort();
    }
    memcpy(s_template, blob, len);
    s_template_len = len;
    s_template_tail = tail;
    fuzz_dht_stub_reset();
}
#endif /* !FUZZ_CONTACTLIST_RAW_ONLY */

static void init_once(void) {
    if (s_ready) {
        return;
    }
    qgp_log_set_level(QGP_LOG_LEVEL_NONE);
    s_self = calloc(1, sizeof(*s_self));
    if (!s_self || fuzz_identity_derive(s_self, FUZZ_ID_SELF) != 0) {
        abort();
    }
#ifndef FUZZ_CONTACTLIST_RAW_ONLY
    init_template();
#endif
    s_ready = 1;
}

static void fetch_and_free(void) {
    char **contacts = NULL;
    size_t count = 0;
    uint8_t **salts = NULL;
    if (dht_contactlist_fetch(s_self->fp_hex, &contacts, &count, &salts,
                              s_self->kyber_sk, s_self->sign_pk) == 0) {
        dht_contactlist_free_salts(salts, count);
        dht_contactlist_free_contacts(contacts, count);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    init_once();

    const uint8_t *body = data + 1;
    size_t body_len = size - 1;

#ifndef FUZZ_CONTACTLIST_RAW_ONLY
    if ((data[0] & 1) == 0)
#endif
    {
        const uint8_t *vals[1] = { body };
        size_t lens[1] = { body_len };
        fuzz_dht_stub_load(vals, lens, 1);
        fetch_and_free();
        fuzz_dht_stub_reset();
        return 0;
    }

#ifndef FUZZ_CONTACTLIST_RAW_ONLY
    /* sealed: seal the fuzzed JSON exactly as the publisher does */
    uint8_t *seal = NULL;
    size_t seal_len = 0;
    if (dna_encrypt_message_raw(s_ctx, body, body_len,
                                s_self->kyber_pk, s_self->sign_pk, s_self->sign_sk,
                                1700000000ull, &seal, &seal_len) != DNA_OK) {
        return 0;
    }
    size_t tail_len = s_template_len - s_template_tail;
    size_t blob_len = CL_HEADER_BYTES + CL_ENC_LEN_BYTES + seal_len + tail_len;
    uint8_t *blob = malloc(blob_len);
    if (!blob) {
        free(seal);
        return 0;
    }
    memcpy(blob, s_template, CL_HEADER_BYTES);
    wr_be32(blob + CL_HEADER_BYTES, (uint32_t)seal_len);
    memcpy(blob + CL_HEADER_BYTES + CL_ENC_LEN_BYTES, seal, seal_len);
    memcpy(blob + CL_HEADER_BYTES + CL_ENC_LEN_BYTES + seal_len,
           s_template + s_template_tail, tail_len);
    free(seal);

    const uint8_t *vals[1] = { blob };
    size_t lens[1] = { blob_len };
    fuzz_dht_stub_load(vals, lens, 1);
    free(blob);
    fetch_and_free();
    fuzz_dht_stub_reset();
    return 0;
#endif
}
