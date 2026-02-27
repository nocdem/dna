/**
 * DHT-based Keyserver Implementation (FACADE)
 * Decentralized public key storage and lookup
 *
 * Architecture: Modular design with focused responsibilities
 * - keyserver/keyserver_helpers.c: Shared helper functions
 * - keyserver/keyserver_publish.c: Publishing operations
 * - keyserver/keyserver_lookup.c: Lookup operations
 * - keyserver/keyserver_names.c: DNA name system
 * - keyserver/keyserver_profiles.c: Profile management
 * - keyserver/keyserver_addresses.c: Address resolution
 *
 * This facade file provides backward compatibility with existing API.
 * All functions forward to the appropriate module.
 *
 * DHT Key Format: SHA3-512(identity + ":pubkey") - 128 hex chars
 */

#include "dht_keyserver.h"

// All module functions are already declared in dht_keyserver.h
// This facade file simply ensures the API is available for linking.
// The actual implementations are in the keyserver/ modules.

// Note: All function implementations have been moved to:
// - keyserver/keyserver_publish.c (dht_keyserver_publish, _publish_alias, _update, _delete, _free_entry)
// - keyserver/keyserver_lookup.c (dht_keyserver_lookup, _reverse_lookup, _reverse_lookup_async)
// - keyserver/keyserver_names.c (dna_compute_fingerprint, dna_register_name, dna_renew_name, dna_lookup_by_name, dna_is_name_expired)
// - keyserver/keyserver_profiles.c (dna_update_profile, dna_load_identity, dna_get_display_name)
// - keyserver/keyserver_addresses.c (dna_resolve_address)
//
// The header file dht_keyserver.h remains unchanged, maintaining backward compatibility.
