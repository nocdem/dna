/**
 * @file fuzz_anchor_json.c
 * @brief libFuzzer harness: Anchor (profile / identity) record JSON parser.
 *
 * Entry points (exported, compiled into this target unchanged from
 * messenger/dht/client/dna_profile.c so libFuzzer sees their coverage):
 *   dna_identity_from_json         dna_profile.c:254 (dna_profile.h:158)
 *   dna_identity_to_json_unsigned  dna_profile.c:250
 *   dna_identity_to_json           dna_profile.c:246
 *   dna_identity_free              dna_profile.h:127
 *
 * Anyone can publish an Anchor record under their own key and every client
 * that looks the name/fingerprint up parses it, so the JSON is fully
 * attacker-chosen (web Connect design rev 5 §1.2 "Anchor record codec", §5
 * A5/A10). After a successful parse the record is re-serialised exactly as
 * the signature check does (keyserver_lookup.c verifies over
 * dna_identity_to_json_unsigned), so the encoder also runs on every field
 * combination the parser accepts — including the intake ek_check path for
 * "mlkem_pubkey" (dna_profile.c, D9).
 *
 * This is NOT fuzz_profile_json: that target exercises a copy of the legacy
 * dht_profile.c string scanner, a different record.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "dht/client/dna_profile.h"
#include "crypto/utils/qgp_log.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int s_init;
    if (!s_init) {
        qgp_log_set_level(QGP_LOG_LEVEL_NONE);   /* parse errors log per input */
        s_init = 1;
    }

    /* dna_identity_from_json takes a NUL-terminated string */
    char *json = malloc(size + 1);
    if (!json) {
        return 0;
    }
    if (size) {
        memcpy(json, data, size);
    }
    json[size] = '\0';

    dna_unified_identity_t *identity = NULL;
    if (dna_identity_from_json(json, &identity) == 0 && identity) {
        char *unsigned_json = dna_identity_to_json_unsigned(identity);
        free(unsigned_json);
        char *signed_json = dna_identity_to_json(identity);
        free(signed_json);
        dna_identity_free(identity);
    }

    free(json);
    return 0;
}
