/*
 * DNA Messenger - PostgreSQL Implementation
 *
 * Phase 3: Local PostgreSQL (localhost)
 * Phase 4: Network PostgreSQL (remote server)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#ifdef _WIN32
#include <windows.h>
#define popen _popen
#define pclose _pclose
// Windows doesn't have htonll/ntohll, define them
#define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)
#else
#include <sys/time.h>
#include <unistd.h>  // For unlink(), close()
#include <arpa/inet.h>  // For htonl, htonll
// Define htonll/ntohll if not available
#ifndef htonll
#define htonll(x) ((1==htonl(1)) ? (x) : (((uint64_t)htonl((x) & 0xFFFFFFFF)) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)
#endif
#endif
#include <json-c/json.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include "messenger.h"
#include "messenger_p2p.h"  // Phase 9.1b: P2P delivery integration
#include "dna_config.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_kyber.h"
#include "crypto/utils/qgp_sha3.h"  // For SHA3-512 fingerprint computation
#include "dht/client/dht_singleton.h"  // Global DHT singleton
#include "crypto/utils/qgp_types.h"  // For qgp_key_load, qgp_key_free
#include "qgp.h"  // For cmd_gen_key_from_seed, cmd_export_pubkey
#include "crypto/bip39/bip39.h"  // For BIP39_MAX_MNEMONIC_LENGTH, bip39_validate_mnemonic, qgp_derive_seeds_from_mnemonic
#include "crypto/utils/kyber_deterministic.h"  // For crypto_kem_keypair_derand
#include "crypto/utils/qgp_aes.h"  // For qgp_aes256_encrypt
#include "crypto/utils/aes_keywrap.h"  // For aes256_wrap_key
#include "crypto/utils/qgp_random.h"  // For qgp_randombytes
#include "database/keyserver_cache.h"  // Phase 4: Keyserver cache
#include "dht/core/dht_keyserver.h"   // Phase 9.4: DHT-based keyserver
#include "dht/core/dht_context.h"     // Phase 9.4: DHT context management
#include "dht/client/dht_contactlist.h" // DHT contact list sync
#include "p2p/p2p_transport.h"   // For getting DHT context
#include "database/contacts_db.h"         // Phase 9.4: Local contacts database
#include "messenger/identity.h"  // Phase: Modularization - Identity utilities
#include "messenger/init.h"      // Phase: Modularization - Context management
#include "messenger/status.h"    // Phase: Modularization - Message status
#include "messenger/keys.h"      // Phase: Modularization - Public key management
#include "messenger/contacts.h"  // Phase: Modularization - DHT contact sync
#include "messenger/keygen.h"    // Phase: Modularization - Key generation
#include "messenger/messages.h"  // Phase: Modularization - Message operations

// Global configuration
static dna_config_t g_config;

// ============================================================================
// INITIALIZATION
// ============================================================================
// MODULARIZATION: Moved to messenger/init.{c,h}

/*
 * resolve_identity_to_fingerprint() - MOVED to messenger/init.c (static helper)
 * messenger_init() - MOVED to messenger/init.c
 * messenger_free() - MOVED to messenger/init.c
 * messenger_load_dht_identity() - MOVED to messenger/init.c
 */
// ============================================================================
// KEY GENERATION
// ============================================================================
// MODULARIZATION: Moved to messenger/keygen.{c,h}

/*
 * messenger_generate_keys() - MOVED to messenger/keygen.c
 * messenger_generate_keys_from_seeds() - MOVED to messenger/keygen.c
 * messenger_register_name() - MOVED to messenger/keygen.c
 * messenger_restore_keys() - MOVED to messenger/keygen.c
 * messenger_restore_keys_from_file() - MOVED to messenger/keygen.c
 */

// ============================================================================
// FINGERPRINT UTILITIES (Phase 4: Fingerprint-First Identity)
// ============================================================================
// MODULARIZATION: Moved to messenger/identity.{c,h}

/*
 * messenger_compute_identity_fingerprint() - MOVED to messenger/identity.c
 * messenger_is_fingerprint() - MOVED to messenger/identity.c
 * messenger_get_display_name() - MOVED to messenger/identity.c
 */

// ============================================================================
// PUBLIC KEY MANAGEMENT
// ============================================================================
// MODULARIZATION: Moved to messenger/keys.{c,h}

/*
 * base64_encode() - MOVED to messenger/keys.c (static helper)
 * base64_decode() - MOVED to messenger/keys.c (static helper)
 * messenger_store_pubkey() - MOVED to messenger/keys.c
 * messenger_load_pubkey() - MOVED to messenger/keys.c
 * messenger_list_pubkeys() - MOVED to messenger/keys.c
 * messenger_get_contact_list() - MOVED to messenger/keys.c
 */


// ============================================================================
// MESSAGE OPERATIONS
// ============================================================================
// MODULARIZATION: Moved to messenger/messages.{c,h}

/*
 * messenger_send_message() - MOVED to messenger/messages.c
 * messenger_list_messages() - MOVED to messenger/messages.c
 * messenger_list_sent_messages() - MOVED to messenger/messages.c
 * messenger_read_message() - MOVED to messenger/messages.c
 * messenger_decrypt_message() - MOVED to messenger/messages.c
 * messenger_delete_pubkey() - MOVED to messenger/messages.c
 * messenger_delete_message() - MOVED to messenger/messages.c
 * messenger_search_by_sender() - MOVED to messenger/messages.c
 * messenger_show_conversation() - MOVED to messenger/messages.c
 * messenger_get_conversation() - MOVED to messenger/messages.c
 * messenger_search_by_date() - MOVED to messenger/messages.c
 */

// ============================================================================
// GROUP MANAGEMENT
// ============================================================================
// MODULARIZATION: Legacy PostgreSQL functions removed (Phase 3)
// Active DHT-based group functions in messenger_groups.c:
//   - messenger_create_group()
//   - messenger_add_group_member()
//   - messenger_remove_group_member()
//   - messenger_send_group_message()
//   - messenger_list_groups()
//   - messenger_get_group_members()
//   - messenger_delete_group()
//   - messenger_leave_group()
//   - messenger_update_group_info()
//   - messenger_list_group_messages()
//   - messenger_is_group_member()



// ============================================================================
// DHT CONTACT LIST SYNCHRONIZATION
// ============================================================================
// MODULARIZATION: Moved to messenger/contacts.{c,h}

/*
 * messenger_sync_contacts_to_dht() - MOVED to messenger/contacts.c
 * messenger_sync_contacts_from_dht() - MOVED to messenger/contacts.c
 * messenger_contacts_auto_sync() - MOVED to messenger/contacts.c
 */


