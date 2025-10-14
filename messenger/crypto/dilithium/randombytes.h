#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stddef.h>
#include <stdint.h>

// SDK Independence: Use our qgp_randombytes
#include "../../qgp_random.h"
#define randombytes qgp_randombytes

#endif
