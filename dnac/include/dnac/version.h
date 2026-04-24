/**
 * @file version.h
 * @brief DNAC version information
 *
 * DNAC - Post-Quantum Zero-Knowledge Cash
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_VERSION_H
#define DNAC_VERSION_H

#define DNAC_VERSION_MAJOR 0
#define DNAC_VERSION_MINOR 17
#define DNAC_VERSION_PATCH 6

#define DNAC_VERSION_STRING "0.17.6-stake.wip"

/**
 * @brief Get DNAC library version string
 * @return Version string in format "X.Y.Z"
 */
const char* dnac_get_version(void);

/**
 * @brief Get DNAC version components
 * @param major Pointer to store major version (can be NULL)
 * @param minor Pointer to store minor version (can be NULL)
 * @param patch Pointer to store patch version (can be NULL)
 */
void dnac_get_version_components(int *major, int *minor, int *patch);

#endif /* DNAC_VERSION_H */
