#include <stddef.h>
#include <stdint.h>
/* Raw upstream random APIs are intentionally unavailable in this target.
 * Preserve their existing error paths rather than substituting zero bytes. */
int qgp_mldsa_private_randombytes_unavailable(uint8_t *buf, size_t len)
{
    (void)buf;
    return len == 0 ? 0 : -1;
}
