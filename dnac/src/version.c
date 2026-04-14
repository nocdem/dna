/**
 * @file version.c
 * @brief DNAC version implementation
 */

#include "dnac/version.h"
#include "crypto/utils/qgp_safe_string.h"   /* Phase 03: unsafe-string poison guard */

const char* dnac_get_version(void) {
    return DNAC_VERSION_STRING;
}

void dnac_get_version_components(int *major, int *minor, int *patch) {
    if (major) *major = DNAC_VERSION_MAJOR;
    if (minor) *minor = DNAC_VERSION_MINOR;
    if (patch) *patch = DNAC_VERSION_PATCH;
}
