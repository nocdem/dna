/**
 * @file fuzz_salt_packet.c
 * @brief libFuzzer harness: salt-agreement packet parse (v1 / v2).
 *
 * The packet parse (packet_data_size_for_version, packet_verify_signature,
 * packet_decrypt_salt — all static, dht_salt_agreement.c:67-184) and the
 * multi-value dedup / tiebreak sit inside salt_agreement_fetch_internal
 * (static, :401) in a file that also does DHT I/O, and NC-1 moves them in
 * parallel, so this target fuzzes the nearest exported entry point:
 *   salt_agreement_fetch_v2    dht_salt_agreement.c:547
 * with messenger/dht/shared/dht_salt_agreement.c compiled in unchanged and
 * the nodus_ops read replaced by fuzz_dht_stub.c. gek_decrypt_alg
 * (messenger/messenger/gek.c) comes from libdna.so, uninstrumented.
 *
 * Input byte 0 selects the mode:
 *   bit0 = 0  raw:    bytes 1.. are the values the DHT returns for the
 *                     agreement key, each prefixed by a 2-byte big-endian
 *                     length (harness framing only, not a wire format); a
 *                     trailing piece without a complete prefix is the last
 *                     value. Reaches the version peek, the size checks and
 *                     ML-DSA verify; a random packet cannot pass the
 *                     signature check, so packet_decrypt_salt is not reached
 *                     unless the input carries a real signature (the seeds
 *                     do: fuzz_seed_gen writes packets from the real
 *                     publisher, signed by the local key).
 *   bit0 = 1  signed: bytes 1.. are the DATA portion of one packet. The
 *                     harness sizes it for the version it declares
 *                     (v1 3386 / v2 3388 bytes, dht_salt_agreement.c:36-46;
 *                     other versions: as given), signs it with the CONTACT's
 *                     ML-DSA key and appends the signature — the packet a
 *                     malicious contact can legitimately publish (web Connect
 *                     design rev 5 §5 A5/A9). Reaches packet_decrypt_salt and
 *                     gek_decrypt_alg with attacker-chosen fingerprints,
 *                     alg byte and KEM blob.
 *     bit1 = 1        (signed) the local fingerprint is written into entry 1,
 *                     so the decrypt branch is taken without the fuzzer
 *                     having to discover 64 bytes.
 *     bit2 = 1        (signed) the packet is returned twice (dedup path).
 *
 * Keys: fuzz_keys.h FUZZ_ID_SELF (local) and FUZZ_ID_CONTACT, derand.
 * Throughput note: signed mode signs once per input.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "dht/shared/dht_salt_agreement.h"
#include "crypto/sign/qgp_dilithium.h"
#include "crypto/utils/qgp_log.h"
#include "fuzz_keys.h"
#include "fuzz_dht_stub.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* dht_salt_agreement.c:36-46 */
#define SALT_PKT_DATA_V1   3386
#define SALT_PKT_DATA_V2   3388
#define SALT_PKT_FP_OFFSET 2      /* entry 1 fingerprint follows the version */
#define SALT_PKT_FP_BYTES  64

static fuzz_identity_t *s_self;
static fuzz_identity_t *s_contact;

static void init_once(void) {
    if (s_self) {
        return;
    }
    qgp_log_set_level(QGP_LOG_LEVEL_NONE);
    s_self = calloc(1, sizeof(*s_self));
    s_contact = calloc(1, sizeof(*s_contact));
    if (!s_self || !s_contact ||
        fuzz_identity_derive(s_self, FUZZ_ID_SELF) != 0 ||
        fuzz_identity_derive(s_contact, FUZZ_ID_CONTACT) != 0) {
        abort();
    }
}

static void fetch(void) {
    uint8_t salt[SALT_AGREEMENT_SIZE];
    (void)salt_agreement_fetch_v2(s_self->fp_hex, s_contact->fp_hex,
                                  s_self->kyber_sk, s_self->mlkem_sk,
                                  s_self->sign_pk, s_contact->sign_pk, salt);
}

static void run_raw(const uint8_t *p, size_t n) {
    const uint8_t *vals[FUZZ_DHT_STUB_MAX_VALUES];
    size_t lens[FUZZ_DHT_STUB_MAX_VALUES];
    size_t count = 0;
    while (n > 0 && count < FUZZ_DHT_STUB_MAX_VALUES) {
        if (n < 2) {
            vals[count] = p;
            lens[count] = n;
            count++;
            break;
        }
        size_t vlen = ((size_t)p[0] << 8) | p[1];
        p += 2;
        n -= 2;
        if (vlen > n) {
            vlen = n;
        }
        vals[count] = p;
        lens[count] = vlen;
        count++;
        p += vlen;
        n -= vlen;
    }
    fuzz_dht_stub_load(vals, lens, count);
    fetch();
    fuzz_dht_stub_reset();
}

static void run_signed(uint8_t flags, const uint8_t *p, size_t n) {
    size_t data_size = n;
    if (n >= 2) {
        uint16_t version = (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
        if (version == SALT_AGREEMENT_VERSION) {
            data_size = SALT_PKT_DATA_V1;
        } else if (version == SALT_AGREEMENT_VERSION_V2) {
            data_size = SALT_PKT_DATA_V2;
        }
    }

    uint8_t *pkt = calloc(1, data_size + QGP_DSA87_SIGNATURE_BYTES);
    if (!pkt) {
        return;
    }
    memcpy(pkt, p, n < data_size ? n : data_size);
    if ((flags & 2) && data_size >= SALT_PKT_FP_OFFSET + SALT_PKT_FP_BYTES) {
        memcpy(pkt + SALT_PKT_FP_OFFSET, s_self->fp, SALT_PKT_FP_BYTES);
    }
    size_t sig_len = 0;
    if (qgp_dsa87_sign(pkt + data_size, &sig_len, pkt, data_size, s_contact->sign_sk) != 0) {
        free(pkt);
        return;
    }
    const uint8_t *vals[2] = { pkt, pkt };
    size_t lens[2] = { data_size + sig_len, data_size + sig_len };
    fuzz_dht_stub_load(vals, lens, (flags & 4) ? 2 : 1);
    free(pkt);
    fetch();
    fuzz_dht_stub_reset();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }
    init_once();
    if ((data[0] & 1) == 0) {
        run_raw(data + 1, size - 1);
    } else {
        run_signed(data[0], data + 1, size - 1);
    }
    return 0;
}
