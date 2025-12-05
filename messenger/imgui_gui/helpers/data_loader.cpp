#include "data_loader.h"
#include "notification_manager.h"
#include "../../messenger.h"
#include "../../messenger_p2p.h"
#include "../../database/contacts_db.h"
#include "../../database/profile_manager.h"
#include "../../dht/client/dht_singleton.h"
#include "../../p2p/p2p_transport.h"
#include "../screens/profile_editor_screen.h"

extern "C" {
#include "../../crypto/utils/qgp_platform.h"
#include "../../dht/core/dht_keyserver.h"
#include "../../database/group_invitations.h"
#include "../../dht/shared/dht_groups.h"
}

#include <cstring>
#include <cstdio>
#include <algorithm>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#undef STATUS_PENDING  // Undefine Windows macro that conflicts with MessageStatus enum
#else
#include <dirent.h>
#endif

namespace DataLoader {

void scanIdentities(AppState& state) {
    state.identities.clear();

    // Scan ~/.dna for *.dsa files (Dilithium signature keys)
    const char* home = qgp_platform_home_dir();
    if (!home) {
        printf("[Identity] ERROR: Failed to get home directory\n");
        return;
    }

#ifdef _WIN32
    std::string dna_dir = std::string(home) + "\\.dna";
#else
    std::string dna_dir = std::string(home) + "/.dna";
#endif

#ifdef _WIN32
    std::string search_path = dna_dir + "\\*.dsa";
    WIN32_FIND_DATAA find_data;
    HANDLE handle = FindFirstFileA(search_path.c_str(), &find_data);

    if (handle != INVALID_HANDLE_VALUE) {
        do {
            std::string filename = find_data.cFileName;
            // Remove ".dsa" suffix (4 chars)
            if (filename.length() > 4) {
                std::string fingerprint = filename.substr(0, filename.length() - 4);

                // Verify both key files exist (.dsa and .kem)
                std::string dsa_path = dna_dir + "\\" + fingerprint + ".dsa";
                std::string kem_path = dna_dir + "\\" + fingerprint + ".kem";

                struct stat dsa_stat, kem_stat;
                if (stat(dsa_path.c_str(), &dsa_stat) == 0 && stat(kem_path.c_str(), &kem_stat) == 0) {
                    state.identities.push_back(fingerprint);
                }
            }
        } while (FindNextFileA(handle, &find_data));
        FindClose(handle);
    }
#else
    DIR* dir = opendir(dna_dir.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string filename = entry->d_name;
            // Check if filename ends with ".dsa"
            if (filename.length() > 4 && filename.substr(filename.length() - 4) == ".dsa") {
                std::string fingerprint = filename.substr(0, filename.length() - 4);

                // Verify both key files exist (.dsa and .kem)
                std::string dsa_path = dna_dir + "/" + fingerprint + ".dsa";
                std::string kem_path = dna_dir + "/" + fingerprint + ".kem";

                struct stat dsa_stat, kem_stat;
                if (stat(dsa_path.c_str(), &dsa_stat) == 0 && stat(kem_path.c_str(), &kem_stat) == 0) {
                    state.identities.push_back(fingerprint);
                }
            }
        }
        closedir(dir);
    }
#endif

    printf("[Identity] Scanned ~/.dna: found %zu identities\n", state.identities.size());
}

void loadIdentity(AppState& state, const std::string& identity, std::function<void(int)> load_messages_callback) {
    printf("[Identity] Loading identity: %s\n", identity.c_str());

    // Clear existing data
    state.contacts.clear();
    state.contact_messages.clear();

    // Initialize messenger context if not already done
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (ctx == nullptr) {
        ctx = messenger_init(identity.c_str());
        state.messenger_ctx = ctx;
        if (!ctx) {
            printf("[Identity] ERROR: Failed to initialize messenger context\n");
            return;
        }
        printf("[Identity] Messenger context initialized for: %s\n", identity.c_str());

        // Load DHT identity and reinitialize DHT with permanent identity
        if (ctx->fingerprint) {
            printf("[Identity] Loading DHT identity...\n");
            if (messenger_load_dht_identity(ctx->fingerprint) == 0) {
                printf("[Identity] [OK] DHT identity loaded successfully\n");
            } else {
                printf("[Identity] Warning: Failed to load DHT identity (DHT operations may accumulate values)\n");
                // Non-fatal - continue without permanent DHT identity
            }
        } else {
            printf("[Identity] Warning: No fingerprint available, skipping DHT identity loading\n");
        }

        // Initialize P2P transport for DHT and messaging
        if (messenger_p2p_init(ctx) != 0) {
            printf("[Identity] ERROR: Failed to initialize P2P transport\n");
            messenger_free(ctx);
            state.messenger_ctx = nullptr;
            return;
        }
        printf("[Identity] P2P transport initialized\n");

        // Initialize group invitations database
        printf("[Identity] Initializing group invitations database...\n");
        if (group_invitations_init(identity.c_str()) == 0) {
            printf("[Identity] [OK] Group invitations database initialized\n");
        } else {
            printf("[Identity] Warning: Failed to initialize group invitations database\n");
        }

        // Register presence in DHT (announce we're online)
        printf("[Identity] Registering presence in DHT...\n");
        if (messenger_p2p_refresh_presence(ctx) == 0) {
            printf("[Identity] [OK] Presence registered successfully\n");
        } else {
            printf("[Identity] Warning: Failed to register presence\n");
        }

        // Subscribe to all contacts' outboxes for push notifications
        printf("[Identity] Subscribing to contacts for push notifications...\n");
        if (messenger_p2p_subscribe_to_contacts(ctx) == 0) {
            printf("[Identity] [OK] Push notifications enabled\n");
        } else {
            printf("[Identity] Warning: Failed to enable push notifications\n");
        }

        // Initialize profile manager for profile caching
        dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
        if (dht_ctx) {
            printf("[Identity] Initializing profile manager...\n");
            if (profile_manager_init(dht_ctx, ctx->fingerprint) == 0) {
                printf("[Identity] [OK] Profile manager initialized\n");
            } else {
                printf("[Identity] Warning: Failed to initialize profile manager\n");
            }
        }

        // Sync groups and check for pending invitations
        printf("[Identity] Syncing groups and invitations...\n");
        if (messenger_sync_groups(ctx) == 0) {
            printf("[Identity] [OK] Groups synced successfully\n");
        } else {
            printf("[Identity] Warning: Failed to sync groups\n");
        }
        
        // Preload user profile asynchronously for instant Edit Profile
        printf("[Identity] Preloading user profile...\n");
        state.profile_preload_task.start([&state](AsyncTask* task) {
            ProfileEditorScreen::loadProfile(state, false);
            printf("[Identity] User profile preloaded\n");
        });
    }

    // Load contacts from database using messenger API
    char **identities = nullptr;
    int contactCount = 0;

    if (messenger_get_contact_list(ctx, &identities, &contactCount) == 0) {
        printf("[Contacts] Loading %d contacts from database\n", contactCount);

        for (int i = 0; i < contactCount; i++) {
            std::string contact_identity = identities[i];

            // Get display name (registered name or shortened fingerprint)
            char displayName[256] = {0};
            if (messenger_get_display_name(ctx, identities[i], displayName) == 0) {
                // Success - use display name
            } else {
                // Fallback to raw identity
                strncpy(displayName, identities[i], sizeof(displayName) - 1);
            }

            // Check P2P presence system for online status
            bool is_online = messenger_p2p_peer_online(ctx, contact_identity.c_str());

            // Add contact to list
            state.contacts.push_back({
                displayName,           // name
                contact_identity,      // address (fingerprint)
                is_online              // online status
            });

            free(identities[i]);
        }
        free(identities);

        // Sort contacts: online first, then alphabetically
        std::sort(state.contacts.begin(), state.contacts.end(), [](const Contact& a, const Contact& b) {
            if (a.is_online != b.is_online) {
                return a.is_online > b.is_online; // Online first
            }
            return strcmp(a.name.c_str(), b.name.c_str()) < 0; // Then alphabetically
        });

        printf("[Contacts] Loaded %d contacts\n", contactCount);
    } else {
        printf("[Contacts] No contacts found or error loading contacts\n");
    }

    // Load groups for this identity
    printf("[Groups] Loading groups from cache...\n");
    state.groups.clear();

    dht_group_cache_entry_t *groups_array = nullptr;
    int groups_count = 0;
    if (dht_groups_list_for_user(identity.c_str(), &groups_array, &groups_count) == 0 && groups_count > 0) {
        for (int i = 0; i < groups_count; i++) {
            Group group;
            group.local_id = groups_array[i].local_id;
            group.group_uuid = groups_array[i].group_uuid;
            group.name = groups_array[i].name;
            group.creator = groups_array[i].creator;
            // TODO: Query member count from dht_group_members table (local cache)
            // or add member_count column to dht_group_cache table
            group.member_count = 0;
            group.created_at = groups_array[i].created_at;
            group.last_sync = groups_array[i].last_sync;

            state.groups.push_back(group);
        }

        dht_groups_free_cache_entries(groups_array, groups_count);
        printf("[Groups] Loaded %d groups\n", groups_count);
    } else {
        printf("[Groups] No groups found for this identity\n");
    }

    // Load pending invitations
    printf("[Invitations] Loading pending invitations...\n");
    state.pending_invitations.clear();

    group_invitation_t *invitations_array = nullptr;
    int invitations_count = 0;
    if (group_invitations_get_pending(&invitations_array, &invitations_count) == 0 && invitations_count > 0) {
        for (int i = 0; i < invitations_count; i++) {
            GroupInvitation invitation;
            invitation.group_uuid = invitations_array[i].group_uuid;
            invitation.group_name = invitations_array[i].group_name;
            invitation.inviter = invitations_array[i].inviter;
            invitation.invited_at = invitations_array[i].invited_at;
            invitation.status = invitations_array[i].status;
            invitation.member_count = invitations_array[i].member_count;

            state.pending_invitations.push_back(invitation);
        }

        group_invitations_free(invitations_array, invitations_count);
        printf("[Invitations] Found %d pending invitation(s)\n", invitations_count);
    } else {
        printf("[Invitations] No pending invitations\n");
    }

    state.identity_loaded = true;
    state.show_identity_selection = false; // Close identity selection modal
    state.current_identity = identity;

    // Fetch registered DNA name for current identity (synchronous, fast DHT query)
    printf("[Identity] Fetching registered DNA name...\n");
    fetchRegisteredName(state);

    // Model E: Check for offline messages ONCE on login
    printf("[Identity] Checking for offline messages (one-time on login)...\n");
    size_t messages_received = 0;
    int offline_check_result = messenger_p2p_check_offline_messages(ctx, &messages_received);
    if (offline_check_result == 0 && messages_received > 0) {
        printf("[Identity] [OK] Received %zu offline messages on login\n", messages_received);
        state.new_messages_received = true;  // Trigger conversation reload if in a chat
    } else if (offline_check_result == 0) {
        printf("[Identity] No offline messages found\n");
    } else {
        printf("[Identity] Warning: Failed to check offline messages\n");
    }

    // Fetch contacts from DHT in background (sync from other devices)
    state.contacts_synced_from_dht = false;

    state.contact_sync_task.start([&state, ctx](AsyncTask* task) {
        printf("[Contacts] Syncing from DHT...\n");

        // First: Fetch contacts from DHT (merge with local)
        int result = messenger_sync_contacts_from_dht(ctx);
        if (result == 0) {
            printf("[Contacts] [OK] Synced from DHT successfully\n");
            state.contacts_synced_from_dht = true;
        } else {
            printf("[Contacts] DHT sync failed or no data found\n");
        }

        // Second: Push local contacts back to DHT (ensure DHT is up-to-date)
        printf("[Contacts] Publishing local contacts to DHT...\n");
        messenger_sync_contacts_to_dht(ctx);
        printf("[Contacts] [OK] Local contacts published to DHT\n");

        // Third: Refresh expired profiles in background (7-day TTL)
        printf("[Profiles] Refreshing expired profiles from DHT...\n");
        int refreshed = profile_manager_refresh_all_expired();
        if (refreshed > 0) {
            printf("[Profiles] [OK] Refreshed %d expired profiles\n", refreshed);
        } else if (refreshed == 0) {
            printf("[Profiles] No expired profiles to refresh\n");
        }
    });

    // Preload messages for all contacts (improves UX - instant switching)
    printf("[Identity] Preloading messages for %zu contacts...\n", state.contacts.size());
    for (size_t i = 0; i < state.contacts.size(); i++) {
        load_messages_callback(i);
    }

    printf("[Identity] Identity loaded successfully: %s (%zu contacts)\n",
           identity.c_str(), state.contacts.size());

    // Preload user profile asynchronously (AFTER identity loaded and DHT reinitialized)
    // This ensures DHT is fully stabilized before attempting profile operations
    printf("[Identity] Preloading user profile...\n");
    state.profile_preload_task.start([&state](AsyncTask* task) {
        ProfileEditorScreen::loadProfile(state, false);
        printf("[Identity] User profile preloaded\n");
    });
}

void reloadContactsFromDatabase(AppState& state) {
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx) {
        printf("[Contacts] ERROR: No messenger context\n");
        return;
    }

    char **identities = nullptr;
    int contactCount = 0;

    if (messenger_get_contact_list(ctx, &identities, &contactCount) == 0) {
        printf("[Contacts] Reloading %d contacts from database\n", contactCount);

        // Clear existing contacts
        state.contacts.clear();

        for (int i = 0; i < contactCount; i++) {
            std::string contact_identity = identities[i];

            // Get display name
            char displayName[256] = {0};
            if (messenger_get_display_name(ctx, identities[i], displayName) == 0) {
                // Success - use display name
            } else {
                // Fallback to raw identity
                strncpy(displayName, identities[i], sizeof(displayName) - 1);
            }

            bool is_online = false;

            // Add contact to list
            state.contacts.push_back({
                displayName,
                contact_identity,
                is_online
            });

            free(identities[i]);
        }
        free(identities);

        // Sort contacts: online first, then alphabetically
        std::sort(state.contacts.begin(), state.contacts.end(), [](const Contact& a, const Contact& b) {
            if (a.is_online != b.is_online) {
                return a.is_online > b.is_online;
            }
            return strcmp(a.name.c_str(), b.name.c_str()) < 0;
        });

        printf("[Contacts] [OK] Reloaded %d contacts\n", contactCount);
    } else {
        printf("[Contacts] Failed to reload contacts from database\n");
    }
}

void loadMessagesForContact(AppState& state, int contact_index) {
    if (contact_index < 0 || contact_index >= (int)state.contacts.size()) {
        return;
    }

    if (state.message_load_task.isRunning()) {
        return; // Already loading
    }

    const Contact& contact = state.contacts[contact_index];
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx) {
        printf("[Messages] ERROR: No messenger context\n");
        return;
    }

    // Check if messages are already cached (use fingerprint as key)
    std::string contact_address = contact.address;
    if (!state.contact_messages[contact_address].empty()) {
        printf("[Messages] Using cached messages for contact %s (%zu messages)\n",
               contact_address.c_str(), state.contact_messages[contact_address].size());
        return;  // Already loaded, use cache!
    }

    // Copy data for async task
    std::string contact_name = contact.name;
    std::string current_identity = state.current_identity;

    // Load messages asynchronously (capture fingerprint, not index)
    state.message_load_task.start([&state, ctx, contact_address, contact_name, current_identity](AsyncTask* task) {
        printf("[Messages] Loading messages for contact: %s (%s)\n",
               contact_name.c_str(), contact_address.c_str());

        // Load conversation from database
        message_info_t *messages = nullptr;
        int count = 0;

        // Use contact.address which contains the fingerprint
        if (messenger_get_conversation(ctx, contact_address.c_str(), &messages, &count) == 0) {
            printf("[Messages] Loaded %d messages from database\n", count);

            // Build message vector in background thread (don't touch UI yet)
            std::vector<Message> loaded_messages;
            loaded_messages.reserve(count); // Pre-allocate for performance

            for (int i = 0; i < count; i++) {
                // Decrypt message if possible
                char *plaintext = nullptr;
                size_t plaintext_len = 0;

                std::string messageText = "[encrypted]";
                if (messenger_decrypt_message(ctx, messages[i].id, &plaintext, &plaintext_len) == 0) {
                    messageText = std::string(plaintext, plaintext_len);
                    free(plaintext);
                } else {
                    printf("[Messages] Warning: Could not decrypt message ID %d\n", messages[i].id);
                }

                // Format timestamp (extract time from "YYYY-MM-DD HH:MM:SS")
                std::string timestamp = messages[i].timestamp ? messages[i].timestamp : "Unknown";
                if (timestamp.length() >= 16) {
                    // Extract "HH:MM" from "YYYY-MM-DD HH:MM:SS"
                    timestamp = timestamp.substr(11, 5);
                }

                // Determine if message is outgoing (sent by current user)
                bool is_outgoing = false;
                if (messages[i].sender && current_identity.length() > 0) {
                    // Compare fingerprints
                    is_outgoing = (strcmp(messages[i].sender, current_identity.c_str()) == 0);
                }

                // Get sender display name
                std::string sender = contact_name; // Default to contact name for incoming
                if (is_outgoing) {
                    sender = "You";
                } else if (messages[i].sender) {
                    // Try to get display name for sender
                    char displayName[256] = {0};
                    if (messenger_get_display_name(ctx, messages[i].sender, displayName) == 0) {
                        sender = displayName;
                    } else {
                        // Fallback to shortened fingerprint
                        std::string fingerprint = messages[i].sender;
                        if (fingerprint.length() > 32) {
                            sender = fingerprint.substr(0, 16) + "..." + fingerprint.substr(fingerprint.length() - 16);
                        } else {
                            sender = fingerprint;
                        }
                    }
                }

                // Initialize status from database (default to SENT for loaded messages)
                MessageStatus msg_status = STATUS_SENT;  // Default for historical messages
                if (messages[i].status) {
                    // Parse string status (old format compatibility)
                    if (strcmp(messages[i].status, "pending") == 0) {
                        msg_status = STATUS_PENDING;
                    } else if (strcmp(messages[i].status, "failed") == 0) {
                        msg_status = STATUS_FAILED;
                    }
                }

                // Add message to temporary vector (not UI yet)
                Message msg;
                msg.sender = sender;
                msg.content = messageText;
                msg.timestamp = timestamp;
                msg.is_outgoing = is_outgoing;
                msg.status = msg_status;
                msg.message_type = messages[i].message_type;  // Phase 6.2: Copy message type (0=chat, 1=group_invitation)

                loaded_messages.push_back(msg);
            }

            // Free messages array
            messenger_free_messages(messages, count);

            // Atomic swap: replace UI vector in one operation (FAST!)
            state.contact_messages[contact_address] = std::move(loaded_messages);

            printf("[Messages] Processed %d messages for display\n", count);
        } else {
            printf("[Messages] No messages found or error loading conversation\n");
        }
    });
}

void fetchRegisteredName(AppState& state) {
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !state.identity_loaded) {
        printf("[RegisteredName] Cannot fetch - no identity loaded\n");
        state.profile_registered_name = "";
        return;
    }

    // Get DHT context
    dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
    if (!dht_ctx) {
        printf("[RegisteredName] DHT not available\n");
        state.profile_registered_name = "";
        return;
    }

    // Perform reverse lookup (fingerprint -> registered name)
    char *registered_name = nullptr;
    int result = dht_keyserver_reverse_lookup(dht_ctx, ctx->fingerprint, &registered_name);

    if (result == 0 && registered_name != nullptr) {
        printf("[RegisteredName] Found registered name: %s\n", registered_name);
        state.profile_registered_name = std::string(registered_name);
        free(registered_name);
    } else {
        printf("[RegisteredName] No registered name found (result=%d)\n", result);
        state.profile_registered_name = "";
    }
}

} // namespace DataLoader
