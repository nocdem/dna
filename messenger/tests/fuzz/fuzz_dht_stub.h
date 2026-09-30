/**
 * @file fuzz_dht_stub.h
 * @brief Test doubles for the nodus_ops read/write seam (fuzz builds only).
 *
 * Some parsers the web Connect core will run are static functions inside
 * files that also do the DHT I/O (web Connect design rev 5 §1.3): the
 * contact-list blob parse and JSON parse (dht_contactlist.c), the salt-
 * agreement packet parse (dht_salt_agreement.c). NC-5 does not change
 * non-test source, so the fuzz targets compile those files UNCHANGED and
 * call their exported fetch functions; this file replaces the I/O they call
 * (messenger/dht/shared/nodus_ops.h) with functions that return whatever the
 * harness loaded. The executable's definitions take precedence over the ones
 * in libdna.so.
 *
 * Writes are captured, so the seed generator can run the real publish path
 * and store what it would have put into the DHT.
 */

#ifndef FUZZ_DHT_STUB_H
#define FUZZ_DHT_STUB_H

#include <stdint.h>
#include <stddef.h>

/** Maximum number of values one get_all read returns */
#define FUZZ_DHT_STUB_MAX_VALUES 16

/**
 * Load what the next reads return. `count` values (0..FUZZ_DHT_STUB_MAX_VALUES);
 * nodus_ops_get_str returns values[0] (or "not found" when count == 0),
 * nodus_ops_get_all_str returns all of them. The bytes are copied.
 */
void fuzz_dht_stub_load(const uint8_t *const *values, const size_t *lens, size_t count);

/** Forget loaded values and the captured write. */
void fuzz_dht_stub_reset(void);

/** The last value written through nodus_ops_put_str / _put_str_exclusive
 *  (NULL if none). Valid until the next write or reset. */
const uint8_t *fuzz_dht_stub_last_put(size_t *len_out);

#endif /* FUZZ_DHT_STUB_H */
