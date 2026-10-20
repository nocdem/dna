/**
 * @file version.h
 * @brief DNAC version information
 *
 * DNAC - DNA Chain
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_VERSION_H
#define DNAC_VERSION_H

#define DNAC_VERSION_MAJOR 0
#define DNAC_VERSION_MINOR 22
#define DNAC_VERSION_PATCH 2

#define DNAC_VERSION_STRING "0.22.2"

/**
 * @brief Get DNAC library version string
 * @return Version string in format "X.Y.Z"
 */
const char* dnac_get_version(void);

#endif /* DNAC_VERSION_H */
