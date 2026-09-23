#include <stdio.h>
#include "cellframe_wallet_create.h"
#include "crypto/utils/qgp_log.h"
// Only discarded/unreachable RNG and logging glue; native derivation uses OpenSSL.
int qgp_randombytes(unsigned char *out, size_t len) { return -1; }
void qgp_log_message(qgp_log_level_t level, const char *tag, const char *format, ...) {}
int main(int argc, char **argv) {
    unsigned char seed[32]; char address[128];
    if (argc != 2 || cellframe_derive_seed_from_mnemonic(argv[1], seed) || cellframe_wallet_derive_address(seed, address)) return 1;
    puts(address); return 0;
}
bool qgp_log_should_log(qgp_log_level_t level, const char *tag) { return false; }
void qgp_log_ring_add(qgp_log_level_t level, const char *tag, const char *fmt, ...) {}
void qgp_log_file_write(qgp_log_level_t level, const char *tag, const char *fmt, ...) {}
