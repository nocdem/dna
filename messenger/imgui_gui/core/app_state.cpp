#include "app_state.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

AppState::AppState() {
    current_view = VIEW_CONTACTS;
    selected_contact = -1;
    prev_selected_contact = -1;
    should_focus_input = false;
    input_cursor_pos = -1;
    show_wallet = false;
    show_identity_selection = true;
    is_first_frame = true;
    loading_start_time = 0.0f;
    show_operation_spinner = false;
    identity_loaded = false;
    identities_scanned = false;
    selected_identity_idx = -1;
    create_identity_step = STEP_NAME;
    restore_identity_step = RESTORE_STEP_SEED;
    seed_confirmed = false;
    seed_copied = false;
    seed_copied_timer = 0.0f;
    show_emoji_picker = false;
    emoji_picker_pos = ImVec2(0, 0);
    memset(new_identity_name, 0, sizeof(new_identity_name));
    memset(generated_mnemonic, 0, sizeof(generated_mnemonic));
    memset(message_input, 0, sizeof(message_input));
    messenger_ctx = nullptr;
}

void AppState::scanIdentities() {
    identities.clear();

    // UI SKETCH MODE - Add mock identities for testing
    identities.push_back("alice");
    identities.push_back("bob");
    identities.push_back("charlie");
    identities.push_back("david");
    identities.push_back("emma");
    identities.push_back("frank");
    identities.push_back("grace");
    identities.push_back("henry");
    identities.push_back("isabella");
    identities.push_back("jack");
    identities.push_back("kate");
    identities.push_back("liam");
    identities.push_back("maria");
    identities.push_back("noah");
    identities.push_back("olivia");
    identities.push_back("peter");
    identities.push_back("quinn");
    identities.push_back("rachel");
    identities.push_back("steve");
    identities.push_back("tina");
    identities.push_back("ulysses");
    identities.push_back("victoria");
    identities.push_back("william");

    printf("[SKETCH MODE] Loaded %zu mock identities\n", identities.size());

    /* DISABLED FOR SKETCH MODE - Real identity scanning
    // Scan ~/.dna for *-dilithium.pqkey files
    const char* home = getenv("HOME");
    if (!home) return;

    std::string dna_dir = std::string(home) + "/.dna";

#ifdef _WIN32
    std::string search_path = dna_dir + "\\*-dilithium.pqkey";
    WIN32_FIND_DATAA find_data;
    HANDLE handle = FindFirstFileA(search_path.c_str(), &find_data);

    if (handle != INVALID_HANDLE_VALUE) {
        do {
            std::string filename = find_data.cFileName;
            // Remove "-dilithium.pqkey" suffix (17 chars)
            std::string identity = filename.substr(0, filename.length() - 17);
            identities.push_back(identity);
        } while (FindNextFileA(handle, &find_data));
        FindClose(handle);
    }
#else
    DIR* dir = opendir(dna_dir.c_str());
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            std::string filename = entry->d_name;
            if (filename.length() > 17 &&
                filename.substr(filename.length() - 17) == "-dilithium.pqkey") {
                std::string identity = filename.substr(0, filename.length() - 17);
                identities.push_back(identity);
            }
        }
        closedir(dir);
    }
#endif
    */
}

void AppState::loadIdentity(const std::string& identity) {
    printf("[SKETCH MODE] Loading identity: %s\n", identity.c_str());

    // UI SKETCH MODE - Load 100 mock contacts with random online/offline
    contacts.clear();
    contact_messages.clear();

    const char* names[] = {
        "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry",
        "Ivy", "Jack", "Kate", "Liam", "Mia", "Noah", "Olivia", "Peter",
        "Quinn", "Ruby", "Sam", "Tara", "Uma", "Victor", "Wendy", "Xander",
        "Yara", "Zack", "Aiden", "Bella", "Caleb", "Daisy", "Ethan", "Fiona",
        "George", "Hannah", "Isaac", "Julia", "Kevin", "Luna", "Mason", "Nina",
        "Oscar", "Penny", "Quincy", "Rose", "Seth", "Tina", "Ulysses", "Vera",
        "Wade", "Xena", "Yasmin", "Zane", "Aaron", "Bianca", "Colin", "Daphne",
        "Elijah", "Freya", "Gavin", "Hazel", "Ian", "Jade", "Kyle", "Leah",
        "Marcus", "Nora", "Owen", "Piper", "Quentin", "Rachel", "Simon", "Thea",
        "Upton", "Violet", "Walter", "Willow", "Xavier", "Yvonne", "Zachary", "Aria",
        "Blake", "Chloe", "Dylan", "Emma", "Felix", "Gemma", "Hugo", "Iris",
        "James", "Kylie", "Lucas", "Maya", "Nathan", "Olive", "Paul", "Qiana",
        "Ryan", "Sage", "Thomas", "Unity"
    };

    // Generate 100 contacts with random online/offline (60% online, 40% offline)
    srand(12345); // Fixed seed for consistent mock data
    for (int i = 0; i < 100; i++) {
        bool is_online = (rand() % 100) < 60; // 60% online
        char address[64];
        snprintf(address, sizeof(address), "%s@dna", names[i]);
        contacts.push_back({names[i], address, is_online});
    }

    // Sort contacts: online first, then offline
    std::sort(contacts.begin(), contacts.end(), [](const Contact& a, const Contact& b) {
        if (a.is_online != b.is_online) {
            return a.is_online > b.is_online; // Online first
        }
        return strcmp(a.name.c_str(), b.name.c_str()) < 0; // Then alphabetically
    });

    // Mock message history for first contact
    contact_messages[0].push_back({contacts[0].name, "Hey! How are you?", "Today 10:30 AM", false});
    contact_messages[0].push_back({"Me", "I'm good! Working on DNA Messenger", "Today 10:32 AM", true});
    contact_messages[0].push_back({contacts[0].name, "Nice! Post-quantum crypto is the future", "Today 10:33 AM", false});
    contact_messages[0].push_back({"Me", "Absolutely! Kyber1024 + Dilithium5", "Today 10:35 AM", true});
    contact_messages[0].push_back({contacts[0].name, "Can't wait to try it out!", "Today 10:36 AM", false});

    // Mock message history for second contact
    contact_messages[1].push_back({contacts[1].name, "Are you available tomorrow?", "Yesterday 3:45 PM", false});
    contact_messages[1].push_back({"Me", "Yes, what's up?", "Yesterday 4:12 PM", true});
    contact_messages[1].push_back({contacts[1].name, "Let's discuss the new features", "Yesterday 4:15 PM", false});

    printf("[SKETCH MODE] Loaded %zu mock contacts (sorted: online first)\n", contacts.size());

    current_identity = identity;
    identity_loaded = true;
    show_identity_selection = false;

    printf("[SKETCH MODE] Identity loaded successfully!\n");
}
