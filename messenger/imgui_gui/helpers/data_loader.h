#ifndef DATA_LOADER_H
#define DATA_LOADER_H

#include "../core/app_state.h"
#include <string>
#include <functional>

namespace DataLoader {
    // Scan ~/.dna for identity files (*.dsa + *.kem pairs)
    void scanIdentities(AppState& state);

    // Load identity and initialize messenger context
    // load_messages_callback: Called to load messages for each contact after identity loads
    void loadIdentity(AppState& state, const std::string& identity, std::function<void(int)> load_messages_callback);

    // Reload contacts from database (fast refresh without messenger reinit)
    void reloadContactsFromDatabase(AppState& state);

    // Load messages for a specific contact from database (async)
    void loadMessagesForContact(AppState& state, int contact_index);

    // Check DHT offline queue for new messages (async)
    void checkForNewMessages(AppState& state);

    // Fetch registered DNA name for current identity (async)
    void fetchRegisteredName(AppState& state);
}

#endif // DATA_LOADER_H
