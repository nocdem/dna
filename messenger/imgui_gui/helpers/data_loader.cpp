#include "data_loader.h"
#include "../../messenger.h"
#include "../../messenger_p2p.h"
#include "../../database/contacts_db.h"
#include "../../database/profile_manager.h"
#include "../../dht/dht_singleton.h"
#include "../../p2p/p2p_transport.h"

extern "C" {
#include "../../crypto/utils/qgp_platform.h"
}

#include <cstring>
#include <cstdio>
#include <algorithm>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
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
                printf("[Identity] ✓ DHT identity loaded successfully\n");
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

        // Register presence in DHT (announce we're online)
        printf("[Identity] Registering presence in DHT...\n");
        if (messenger_p2p_refresh_presence(ctx) == 0) {
            printf("[Identity] ✓ Presence registered successfully\n");
        } else {
            printf("[Identity] Warning: Failed to register presence\n");
        }

        // Initialize profile manager for profile caching
        dht_context_t *dht_ctx = p2p_transport_get_dht_context(ctx->p2p_transport);
        if (dht_ctx) {
            printf("[Identity] Initializing profile manager...\n");
            if (profile_manager_init(dht_ctx, ctx->fingerprint) == 0) {
                printf("[Identity] ✓ Profile manager initialized\n");
            } else {
                printf("[Identity] Warning: Failed to initialize profile manager\n");
            }
        }
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

    state.identity_loaded = true;
    state.show_identity_selection = false; // Close identity selection modal
    state.current_identity = identity;

    // Model E: Check for offline messages ONCE on login
    printf("[Identity] Checking for offline messages (one-time on login)...\n");
    size_t messages_received = 0;
    int offline_check_result = messenger_p2p_check_offline_messages(ctx, &messages_received);
    if (offline_check_result == 0 && messages_received > 0) {
        printf("[Identity] ✓ Received %zu offline messages on login\n", messages_received);
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
            printf("[Contacts] ✓ Synced from DHT successfully\n");
            state.contacts_synced_from_dht = true;
        } else {
            printf("[Contacts] DHT sync failed or no data found\n");
        }

        // Second: Push local contacts back to DHT (ensure DHT is up-to-date)
        printf("[Contacts] Publishing local contacts to DHT...\n");
        messenger_sync_contacts_to_dht(ctx);
        printf("[Contacts] ✓ Local contacts published to DHT\n");

        // Third: Refresh expired profiles in background (7-day TTL)
        printf("[Profiles] Refreshing expired profiles from DHT...\n");
        int refreshed = profile_manager_refresh_all_expired();
        if (refreshed > 0) {
            printf("[Profiles] ✓ Refreshed %d expired profiles\n", refreshed);
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

        printf("[Contacts] ✓ Reloaded %d contacts\n", contactCount);
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

    // Check if messages are already cached
    if (!state.contact_messages[contact_index].empty()) {
        printf("[Messages] Using cached messages for contact %d (%zu messages)\n",
               contact_index, state.contact_messages[contact_index].size());
        return;  // Already loaded, use cache!
    }

    // Copy data for async task
    std::string contact_address = contact.address;
    std::string contact_name = contact.name;
    std::string current_identity = state.current_identity;

    // Load messages asynchronously
    state.message_load_task.start([&state, ctx, contact_index, contact_address, contact_name, current_identity](AsyncTask* task) {
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

                loaded_messages.push_back(msg);
            }

            // Free messages array
            messenger_free_messages(messages, count);

            // Atomic swap: replace UI vector in one operation (FAST!)
            state.contact_messages[contact_index] = std::move(loaded_messages);

            printf("[Messages] Processed %d messages for display\n", count);
        } else {
            printf("[Messages] No messages found or error loading conversation\n");
        }
    });
}

void checkForNewMessages(AppState& state) {
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    if (!ctx || !state.identity_loaded) {
        return;
    }

    // Don't start a new poll if one is already running
    if (state.message_poll_task.isRunning()) {
        return;
    }

    // Start async poll task
    state.message_poll_task.start([&state, ctx](AsyncTask* task) {
        size_t messages_received = 0;

        // 1. Refresh our presence in DHT (announce we're online)
        printf("[Poll] Refreshing presence in DHT...\n");
        messenger_p2p_refresh_presence(ctx);

        // 2. Check DHT offline queue for new messages
        int result = messenger_p2p_check_offline_messages(ctx, &messages_received);

        if (result == 0 && messages_received > 0) {
            printf("[Poll] ✓ Received %zu new message(s) from DHT offline queue\n", messages_received);
            // Set flag for main thread to reload messages
            state.new_messages_received = true;
        } else if (result != 0) {
            printf("[Poll] Warning: Error checking offline messages\n");
        }

        // 3. Note: Contact presence update happens in main thread when reloading contacts
        // (loadContactsForIdentity calls messenger_p2p_peer_online for each contact)
    });
}

} // namespace DataLoader
