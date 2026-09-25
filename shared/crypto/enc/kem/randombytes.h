#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

// SDK Independence: Use our qgp_randombytes (same shim as
// shared/crypto/sign/dsa/randombytes.h) — deviation #2, see CMakeLists.txt.
#include "crypto/utils/qgp_random.h"
#define randombytes qgp_randombytes

#endif
