/**
 * @file version.c
 * @brief DNAC version implementation
 */

#include "dnac/version.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

const char* dnac_get_version(void) {
    return DNAC_VERSION_STRING;
}
