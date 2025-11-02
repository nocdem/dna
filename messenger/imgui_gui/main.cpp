// DNA Messenger - ImGui GUI
// Modern, lightweight, cross-platform messenger interface

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "IconsFontAwesome6.h"
#include <GLFW/glfw3.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <sys/types.h>
#else
#include <windows.h>
#endif

extern "C" {
#include "../dna_api.h"
#include "../messenger_p2p.h"
#include "../wallet.h"
}

struct Message {
    std::string sender;
    std::string content;
    std::string timestamp;
    bool is_outgoing;
};

struct Contact {
    std::string name;
    std::string address;
    bool is_online;
};

class DNAMessengerApp {
public:
    DNAMessengerApp() {
        current_view = VIEW_CONTACTS;
        selected_contact = -1;
        show_wallet = false;
        show_identity_selection = true;
        identity_loaded = false;
        selected_identity_idx = -1;
        memset(new_identity_name, 0, sizeof(new_identity_name));
    }

    void render() {
        ImGuiIO& io = ImGui::GetIO();
        
        // Show identity selection on first run
        if (show_identity_selection) {
            renderIdentitySelection();
            return;
        }
        
        // Detect screen size for responsive layout
        bool is_mobile = io.DisplaySize.x < 600.0f;
        
        // Main window (fullscreen)
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(io.DisplaySize);
        ImGui::Begin("DNA Messenger", nullptr, 
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | 
            ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse | 
            ImGuiWindowFlags_NoScrollbar);

        // Mobile: Full-screen views with bottom navigation
        // Desktop: Side-by-side layout
        if (is_mobile) {
            renderMobileLayout();
        } else {
            renderDesktopLayout();
        }
        
        ImGui::End();
    }

private:
    enum View {
        VIEW_CONTACTS,
        VIEW_CHAT,
        VIEW_WALLET,
        VIEW_SETTINGS
    };

    View current_view;
    int selected_contact;
    bool show_wallet;
    bool show_identity_selection;
    bool identity_loaded;
    int selected_identity_idx;
    
    std::vector<Contact> contacts;
    std::vector<Message> messages;
    std::vector<std::string> identities;
    std::string current_identity;
    char message_input[1024] = "";
    char new_identity_name[128];
    
    void renderIdentitySelection() {
        ImGuiIO& io = ImGui::GetIO();
        bool is_mobile = io.DisplaySize.x < 600.0f;
        
        // Center the dialog
        ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
        ImGui::SetNextWindowPos(center, ImGuiCond_Always, ImVec2(0.5f, 0.5f));
        ImGui::SetNextWindowSize(ImVec2(is_mobile ? io.DisplaySize.x * 0.9f : 500, is_mobile ? io.DisplaySize.y * 0.9f : 500));
        
        ImGui::Begin("DNA Messenger - Select Identity", nullptr, 
            ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);
        
        // Add padding at top
        ImGui::Spacing();
        ImGui::Spacing();
        
        // Title
        ImGui::SetWindowFontScale(is_mobile ? 1.5f : 1.3f);
        ImGui::Text("Welcome to DNA Messenger");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Info text
        ImGui::TextWrapped("Select an existing identity or create a new one:");
        ImGui::Spacing();
        
        // Load identities on first render
        if (identities.empty()) {
            scanIdentities();
        }
        
        // Identity list
        ImGui::BeginChild("IdentityList", ImVec2(0, -120), true);
        
        if (identities.empty()) {
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1.0f), "No identities found.");
            ImGui::TextWrapped("Create a new identity to get started.");
        } else {
            for (size_t i = 0; i < identities.size(); i++) {
                ImGui::PushID(i);
                bool selected = (selected_identity_idx == (int)i);
                
                if (ImGui::Selectable(identities[i].c_str(), selected, 0, ImVec2(-1, is_mobile ? 50 : 35))) {
                    selected_identity_idx = i;
                }
                
                ImGui::PopID();
            }
        }
        
        ImGui::EndChild();
        
        ImGui::Spacing();
        
        // Buttons
        float btn_height = is_mobile ? 50.0f : 40.0f;
        
        // Select button (only if identity selected)
        ImGui::BeginDisabled(selected_identity_idx < 0);
        if (ImGui::Button(ICON_FA_USER " Select Identity", ImVec2(-1, btn_height))) {
            if (selected_identity_idx >= 0 && selected_identity_idx < (int)identities.size()) {
                current_identity = identities[selected_identity_idx];
                loadIdentity(current_identity);
            }
        }
        ImGui::EndDisabled();
        
        // Create new button
        if (ImGui::Button(ICON_FA_PLUS " Create New Identity", ImVec2(-1, btn_height))) {
            ImGui::OpenPopup("CreateIdentity");
        }
        
        // Create identity popup
        if (ImGui::BeginPopupModal("CreateIdentity", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::Text("Enter identity name:");
            ImGui::Spacing();
            
            ImGui::InputText("##IdentityName", new_identity_name, sizeof(new_identity_name));
            ImGui::Spacing();
            
            if (ImGui::Button("Create", ImVec2(120, 0))) {
                if (strlen(new_identity_name) > 0) {
                    createIdentity(new_identity_name);
                    ImGui::CloseCurrentPopup();
                }
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel", ImVec2(120, 0))) {
                ImGui::CloseCurrentPopup();
            }
            
            ImGui::EndPopup();
        }
        
        ImGui::End();
    }
    
    void scanIdentities() {
        identities.clear();
        
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
    }
    
    void createIdentity(const char* name) {
        // TODO: Call DNA API to create identity
        printf("Creating identity: %s\n", name);
        
        // For now, just add to list and load it
        identities.push_back(name);
        current_identity = name;
        loadIdentity(current_identity);
        
        // Reset input
        memset(new_identity_name, 0, sizeof(new_identity_name));
    }
    
    void loadIdentity(const std::string& identity) {
        printf("Loading identity: %s\n", identity.c_str());
        
        // TODO: Call DNA API to load keys
        
        identity_loaded = true;
        show_identity_selection = false;
        
        // Show success message
        printf("Identity loaded successfully!\n");
    }
    
    void renderMobileLayout() {
        ImGuiIO& io = ImGui::GetIO();
        float screen_height = io.DisplaySize.y;
        float bottom_nav_height = 60.0f;
        
        // Content area (full screen minus bottom nav)
        ImGui::BeginChild("MobileContent", ImVec2(0, -bottom_nav_height), false, ImGuiWindowFlags_NoScrollbar);
        
        switch(current_view) {
            case VIEW_CONTACTS:
                renderContactsList();
                break;
            case VIEW_CHAT:
                renderChatView();
                break;
            case VIEW_WALLET:
                renderWalletView();
                break;
            case VIEW_SETTINGS:
                renderSettingsView();
                break;
        }
        
        ImGui::EndChild();
        
        // Bottom navigation bar
        renderBottomNavBar();
    }
    
    void renderDesktopLayout() {
        // Sidebar (contacts + navigation)
        renderSidebar();
        
        ImGui::SameLine();
        
        // Main content area
        ImGui::BeginChild("MainContent", ImVec2(0, 0), true);
        
        switch(current_view) {
            case VIEW_CONTACTS:
            case VIEW_CHAT:
                renderChatView();
                break;
            case VIEW_WALLET:
                renderWalletView();
                break;
            case VIEW_SETTINGS:
                renderSettingsView();
                break;
        }
        
        ImGui::EndChild();
    }
    
    void renderBottomNavBar() {
        ImGuiIO& io = ImGui::GetIO();
        float btn_width = io.DisplaySize.x / 4.0f;
        
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
        
        // Contacts button
        if (current_view == VIEW_CONTACTS) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.6f));
        }
        if (ImGui::Button(ICON_FA_COMMENTS "\nChats", ImVec2(btn_width, 60))) {
            current_view = VIEW_CONTACTS;
        }
        if (current_view == VIEW_CONTACTS) {
            ImGui::PopStyleColor();
        }
        
        ImGui::SameLine();
        
        // Wallet button
        if (current_view == VIEW_WALLET) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.6f));
        }
        if (ImGui::Button(ICON_FA_WALLET "\nWallet", ImVec2(btn_width, 60))) {
            current_view = VIEW_WALLET;
            selected_contact = -1;
        }
        if (current_view == VIEW_WALLET) {
            ImGui::PopStyleColor();
        }
        
        ImGui::SameLine();
        
        // Settings button
        if (current_view == VIEW_SETTINGS) {
            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.6f));
        }
        if (ImGui::Button(ICON_FA_GEAR "\nSettings", ImVec2(btn_width, 60))) {
            current_view = VIEW_SETTINGS;
            selected_contact = -1;
        }
        if (current_view == VIEW_SETTINGS) {
            ImGui::PopStyleColor();
        }
        
        ImGui::SameLine();
        
        // Profile button (placeholder)
        if (ImGui::Button(ICON_FA_USER "\nProfile", ImVec2(btn_width, 60))) {
            // TODO: Profile view
        }
        
        ImGui::PopStyleVar(2);
    }
    
    void renderContactsList() {
        ImGuiIO& io = ImGui::GetIO();
        
        // Top bar with title and add button
        ImGui::BeginChild("ContactsHeader", ImVec2(0, 60), true, ImGuiWindowFlags_NoScrollbar);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
        
        ImGui::SetWindowFontScale(1.5f);
        ImGui::Text("  DNA Messenger");
        ImGui::SetWindowFontScale(1.0f);
        
        ImGui::SameLine(io.DisplaySize.x - 60);
        if (ImGui::Button(ICON_FA_PLUS, ImVec2(50, 40))) {
            // TODO: Add contact dialog
        }
        
        ImGui::EndChild();
        
        // Contact list (large touch targets)
        ImGui::BeginChild("ContactsScrollArea");
        
        // Demo contacts if empty
        if (contacts.empty()) {
            Contact demo1 = {"Alice", "12345", true};
            Contact demo2 = {"Bob", "67890", false};
            Contact demo3 = {"Charlie", "11111", true};
            contacts.push_back(demo1);
            contacts.push_back(demo2);
            contacts.push_back(demo3);
        }
        
        for (size_t i = 0; i < contacts.size(); i++) {
            ImGui::PushID(i);
            
            // Large touch-friendly buttons (80px height)
            bool selected = (int)i == selected_contact;
            if (selected) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.3f));
            }
            
            if (ImGui::Button("##contact", ImVec2(-1, 80))) {
                selected_contact = i;
                current_view = VIEW_CHAT;
            }
            
            if (selected) {
                ImGui::PopStyleColor();
            }
            
            // Draw contact info on top of button
            ImVec2 button_min = ImGui::GetItemRectMin();
            ImVec2 button_max = ImGui::GetItemRectMax();
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            
            // Online indicator (circle)
            ImVec2 circle_center = ImVec2(button_min.x + 30, button_min.y + 40);
            ImU32 status_color = contacts[i].is_online ? 
                IM_COL32(0, 255, 0, 255) : IM_COL32(128, 128, 128, 255);
            draw_list->AddCircleFilled(circle_center, 8.0f, status_color);
            
            // Contact name
            ImVec2 text_pos = ImVec2(button_min.x + 50, button_min.y + 20);
            draw_list->AddText(ImGui::GetFont(), 20.0f, text_pos, 
                IM_COL32(255, 255, 255, 255), contacts[i].name.c_str());
            
            // Status text
            const char* status = contacts[i].is_online ? "Online" : "Offline";
            ImVec2 status_pos = ImVec2(button_min.x + 50, button_min.y + 45);
            draw_list->AddText(ImGui::GetFont(), 14.0f, status_pos, 
                IM_COL32(180, 180, 180, 255), status);
            
            ImGui::PopID();
        }
        
        ImGui::EndChild();
    }
    
    void renderSidebar() {
        ImGui::BeginChild("Sidebar", ImVec2(250, 0), true);
        
        ImGui::Text("DNA Messenger");
        ImGui::Separator();
        
        // Navigation buttons
        if (ImGui::Button(ICON_FA_COMMENTS " Chat", ImVec2(-1, 40))) {
            current_view = VIEW_CONTACTS;
        }
        if (ImGui::Button(ICON_FA_WALLET " Wallet", ImVec2(-1, 40))) {
            current_view = VIEW_WALLET;
        }
        if (ImGui::Button(ICON_FA_GEAR " Settings", ImVec2(-1, 40))) {
            current_view = VIEW_SETTINGS;
        }
        
        ImGui::Separator();
        ImGui::Text("Contacts");
        ImGui::Separator();
        
        // Contact list
        for (size_t i = 0; i < contacts.size(); i++) {
            ImGui::PushID(i);
            
            // Online indicator
            ImVec4 color = contacts[i].is_online ? 
                ImVec4(0.0f, 1.0f, 0.0f, 1.0f) : ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
            ImGui::TextColored(color, "●");
            ImGui::SameLine();
            
            if (ImGui::Selectable(contacts[i].name.c_str(), 
                selected_contact == (int)i, 0, ImVec2(-1, 30))) {
                selected_contact = i;
                current_view = VIEW_CHAT;
            }
            
            ImGui::PopID();
        }
        
        // Add contact button at bottom
        ImGui::SetCursorPosY(ImGui::GetWindowHeight() - 40);
        if (ImGui::Button(ICON_FA_PLUS " Add Contact", ImVec2(-1, 30))) {
            // TODO: Open add contact dialog
        }
        
        ImGui::EndChild();
    }
    
    void renderChatView() {
        ImGuiIO& io = ImGui::GetIO();
        bool is_mobile = io.DisplaySize.x < 600.0f;
        
        if (selected_contact < 0 || selected_contact >= (int)contacts.size()) {
            if (is_mobile) {
                // On mobile, show contacts list
                current_view = VIEW_CONTACTS;
                return;
            } else {
                ImGui::Text("Select a contact to start chatting");
                return;
            }
        }
        
        Contact& contact = contacts[selected_contact];
        
        // Top bar (mobile: with back button)
        float header_height = is_mobile ? 60.0f : 40.0f;
        ImGui::BeginChild("ChatHeader", ImVec2(0, header_height), true, ImGuiWindowFlags_NoScrollbar);
        
        if (is_mobile) {
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
            if (ImGui::Button(ICON_FA_ARROW_LEFT " Back", ImVec2(100, 40))) {
                current_view = VIEW_CONTACTS;
                selected_contact = -1;
            }
            ImGui::SameLine();
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
        }
        
        ImGui::SetWindowFontScale(is_mobile ? 1.3f : 1.0f);
        ImGui::Text("%s", contact.name.c_str());
        ImGui::SetWindowFontScale(1.0f);
        
        ImGui::SameLine();
        ImGui::TextColored(
            contact.is_online ? ImVec4(0.0f, 1.0f, 0.0f, 1.0f) : ImVec4(0.5f, 0.5f, 0.5f, 1.0f),
            contact.is_online ? "● Online" : "● Offline"
        );
        
        ImGui::EndChild();
        
        // Message area
        float input_height = is_mobile ? 100.0f : 80.0f;
        ImGui::BeginChild("MessageArea", ImVec2(0, -input_height), true);
        
        // Demo messages if empty
        if (messages.empty()) {
            Message demo1 = {"", "Hey! How are you?", "10:30 AM", false};
            Message demo2 = {"", "I'm good! Working on DNA Messenger", "10:32 AM", true};
            Message demo3 = {"", "Nice! Post-quantum crypto is the future 🚀", "10:33 AM", false};
            messages.push_back(demo1);
            messages.push_back(demo2);
            messages.push_back(demo3);
        }
        
        for (size_t i = 0; i < messages.size(); i++) {
            const auto& msg = messages[i];
            
            // Message bubble
            float bubble_width = io.DisplaySize.x * (is_mobile ? 0.75f : 0.5f);
            float indent = msg.is_outgoing ? (io.DisplaySize.x - bubble_width - 20.0f) : 10.0f;
            
            ImGui::SetCursorPosX(indent);
            
            ImGui::PushStyleColor(ImGuiCol_ChildBg, 
                msg.is_outgoing ? ImVec4(0.0f, 0.6f, 0.6f, 0.4f) : ImVec4(0.2f, 0.2f, 0.2f, 0.4f));
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0.0f);
            
            char bubble_id[32];
            snprintf(bubble_id, sizeof(bubble_id), "bubble%zu", i);
            
            ImGui::BeginChild(bubble_id, ImVec2(bubble_width, 0), true, 
                ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoScrollbar);
            
            ImGui::PushTextWrapPos(bubble_width - 20.0f);
            ImGui::SetWindowFontScale(is_mobile ? 1.1f : 1.0f);
            ImGui::Text("%s", msg.content.c_str());
            ImGui::SetWindowFontScale(1.0f);
            ImGui::PopTextWrapPos();
            
            ImGui::SetWindowFontScale(0.85f);
            ImGui::TextDisabled("%s", msg.timestamp.c_str());
            ImGui::SetWindowFontScale(1.0f);
            
            ImGui::EndChild();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor();
            
            ImGui::Spacing();
        }
        
        // Auto-scroll to bottom
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
            ImGui::SetScrollHereY(1.0f);
        
        ImGui::EndChild();
        
        // Message input area
        ImGui::Separator();
        
        if (is_mobile) {
            // Mobile: stacked layout
            ImGui::InputTextMultiline("##MessageInput", message_input, 
                sizeof(message_input), ImVec2(-1, 60));
            
            if (ImGui::Button("Send", ImVec2(-1, 35))) {
                if (strlen(message_input) > 0) {
                    Message msg;
                    msg.content = message_input;
                    msg.is_outgoing = true;
                    msg.timestamp = "Now";
                    messages.push_back(msg);
                    message_input[0] = '\0';
                }
            }
        } else {
            // Desktop: side-by-side
            ImGui::InputTextMultiline("##MessageInput", message_input, 
                sizeof(message_input), ImVec2(-80, 60));
            ImGui::SameLine();
            
            if (ImGui::Button("Send", ImVec2(70, 60))) {
                if (strlen(message_input) > 0) {
                    Message msg;
                    msg.content = message_input;
                    msg.is_outgoing = true;
                    msg.timestamp = "Now";
                    messages.push_back(msg);
                    message_input[0] = '\0';
                }
            }
        }
    }
    
    void renderWalletView() {
        ImGuiIO& io = ImGui::GetIO();
        bool is_mobile = io.DisplaySize.x < 600.0f;
        float padding = is_mobile ? 15.0f : 20.0f;
        
        ImGui::SetCursorPos(ImVec2(padding, padding));
        ImGui::BeginChild("WalletContent", ImVec2(-padding, -padding), false);
        
        // Header
        ImGui::SetWindowFontScale(is_mobile ? 1.5f : 1.3f);
        ImGui::Text(ICON_FA_WALLET " cpunk Wallet");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Token balance cards
        const char* tokens[] = {"CPUNK", "CELL", "KEL"};
        const char* balances[] = {"1,234.56", "89.12", "456.78"};
        
        for (int i = 0; i < 3; i++) {
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12.0f);
            ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.15f, 0.15f, 0.15f, 0.9f));
            
            float card_height = is_mobile ? 100.0f : 120.0f;
            ImGui::BeginChild(tokens[i], ImVec2(-1, card_height), true);
            
            ImGui::SetCursorPos(ImVec2(20, 15));
            ImGui::SetWindowFontScale(is_mobile ? 1.0f : 0.9f);
            ImGui::TextDisabled("%s", tokens[i]);
            ImGui::SetWindowFontScale(1.0f);
            
            ImGui::SetCursorPos(ImVec2(20, is_mobile ? 45 : 50));
            ImGui::SetWindowFontScale(is_mobile ? 1.8f : 2.0f);
            ImGui::Text("%s", balances[i]);
            ImGui::SetWindowFontScale(1.0f);
            
            ImGui::EndChild();
            ImGui::PopStyleColor();
            ImGui::PopStyleVar();
            
            ImGui::Spacing();
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Action buttons
        float btn_height = is_mobile ? 50.0f : 45.0f;
        
        if (is_mobile) {
            // Mobile: Stacked full-width buttons
            if (ImGui::Button(ICON_FA_PAPER_PLANE " Send Tokens", ImVec2(-1, btn_height))) {
                // TODO: Open send dialog
            }
            ImGui::Spacing();
            
            if (ImGui::Button(ICON_FA_DOWNLOAD " Receive", ImVec2(-1, btn_height))) {
                // TODO: Show receive address
            }
            ImGui::Spacing();
            
            if (ImGui::Button(ICON_FA_RECEIPT " Transaction History", ImVec2(-1, btn_height))) {
                // TODO: Show transaction history
            }
        } else {
            // Desktop: Side-by-side buttons
            float btn_width = (io.DisplaySize.x - 80.0f) / 3.0f;
            
            if (ImGui::Button(ICON_FA_PAPER_PLANE " Send", ImVec2(btn_width, btn_height))) {
                // TODO: Open send dialog
            }
            ImGui::SameLine();
            
            if (ImGui::Button(ICON_FA_DOWNLOAD " Receive", ImVec2(btn_width, btn_height))) {
                // TODO: Show receive address
            }
            ImGui::SameLine();
            
            if (ImGui::Button(ICON_FA_RECEIPT " History", ImVec2(btn_width, btn_height))) {
                // TODO: Show transaction history
            }
        }
        
        ImGui::EndChild();
    }
    
    void renderSettingsView() {
        ImGuiIO& io = ImGui::GetIO();
        bool is_mobile = io.DisplaySize.x < 600.0f;
        float padding = is_mobile ? 15.0f : 20.0f;
        
        ImGui::SetCursorPos(ImVec2(padding, padding));
        ImGui::BeginChild("SettingsContent", ImVec2(-padding, -padding), false);
        
        // Header
        ImGui::SetWindowFontScale(is_mobile ? 1.5f : 1.3f);
        ImGui::Text(ICON_FA_GEAR " Settings");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Theme selection
        ImGui::Text("Theme");
        ImGui::Spacing();
        
        static int theme = 0;
        
        if (is_mobile) {
            // Mobile: Full-width radio buttons with larger touch targets
            if (ImGui::RadioButton("cpunk.io (Cyan)##theme", theme == 0)) theme = 0;
            ImGui::Spacing();
            if (ImGui::RadioButton("cpunk.club (Orange)##theme", theme == 1)) theme = 1;
            ImGui::Spacing();
            if (ImGui::RadioButton("Dark Mode##theme", theme == 2)) theme = 2;
        } else {
            ImGui::RadioButton("cpunk.io (Cyan)", &theme, 0);
            ImGui::RadioButton("cpunk.club (Orange)", &theme, 1);
            ImGui::RadioButton("Dark Mode", &theme, 2);
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Identity section
        ImGui::Text("Identity");
        ImGui::Spacing();
        ImGui::TextDisabled("Not loaded");
        ImGui::Spacing();
        
        float btn_height = is_mobile ? 50.0f : 40.0f;
        
        if (is_mobile) {
            if (ImGui::Button("🆕 Create New Identity", ImVec2(-1, btn_height))) {
                // TODO: Create identity dialog
            }
            ImGui::Spacing();
            
            if (ImGui::Button("📥 Import Identity", ImVec2(-1, btn_height))) {
                // TODO: Import identity dialog
            }
        } else {
            if (ImGui::Button("Create New Identity", ImVec2(200, btn_height))) {
                // TODO: Create identity dialog
            }
            ImGui::SameLine();
            if (ImGui::Button("Import Identity", ImVec2(200, btn_height))) {
                // TODO: Import identity dialog
            }
        }
        
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // App info
        ImGui::TextDisabled("DNA Messenger v0.1");
        ImGui::TextDisabled("Post-Quantum Encrypted Messaging");
        
        ImGui::EndChild();
    }
};

static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int argc, char** argv) {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1280, 720, "DNA Messenger", nullptr, nullptr);
    if (window == nullptr)
        return 1;

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    // Load fonts
    ImFontConfig config;
    config.MergeMode = false;
    config.GlyphMinAdvanceX = 13.0f;
    
    // Default font (larger for better readability)
    io.Fonts->AddFontFromFileTTF("imgui_gui/misc/fonts/Roboto-Medium.ttf", 18.0f);
    
    // Merge Font Awesome icons
    config.MergeMode = true;
    config.GlyphMinAdvanceX = 18.0f;
    config.GlyphOffset = ImVec2(0, 2);
    static const ImWchar icon_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
    io.Fonts->AddFontFromFileTTF("imgui_gui/misc/fonts/fa-solid-900.ttf", 16.0f, &config, icon_ranges);
    
    // Don't call Build() - backend will do it automatically

    ImGui::StyleColorsDark();
    
    // DNA Messenger color scheme
    ImGuiStyle& style = ImGui::GetStyle();
    
    // Colors
    ImVec4 bg_main = ImVec4(0x15/255.0f, 0x17/255.0f, 0x19/255.0f, 1.0f);  // #151719
    ImVec4 bg_popup = ImVec4(0x0f/255.0f, 0x11/255.0f, 0x13/255.0f, 1.0f); // Darker for popups
    ImVec4 text_primary = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 1.0f); // #00FFCC (cyan)
    ImVec4 text_secondary = ImVec4(0x80/255.0f, 0xff/255.0f, 0xe6/255.0f, 1.0f); // Lighter cyan
    ImVec4 accent = ImVec4(0x00/255.0f, 0xcc/255.0f, 0xa3/255.0f, 1.0f); // Darker cyan for buttons
    ImVec4 accent_hover = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 1.0f); // Bright cyan on hover
    
    // Main colors
    style.Colors[ImGuiCol_WindowBg] = bg_main;
    style.Colors[ImGuiCol_ChildBg] = bg_main;
    style.Colors[ImGuiCol_PopupBg] = bg_popup;
    style.Colors[ImGuiCol_Border] = ImVec4(0.2f, 0.2f, 0.2f, 0.5f);
    
    // Text
    style.Colors[ImGuiCol_Text] = text_primary;
    style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
    style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 0.3f);
    
    // Buttons
    style.Colors[ImGuiCol_Button] = accent;
    style.Colors[ImGuiCol_ButtonHovered] = accent_hover;
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0x00/255.0f, 0xdd/255.0f, 0xaa/255.0f, 1.0f);
    
    // Headers (selectables, etc)
    style.Colors[ImGuiCol_Header] = ImVec4(0x00/255.0f, 0xcc/255.0f, 0xa3/255.0f, 0.3f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 0.4f);
    style.Colors[ImGuiCol_HeaderActive] = ImVec4(0x00/255.0f, 0xff/255.0f, 0xcc/255.0f, 0.5f);
    
    // Frames (inputs, etc)
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.1f, 0.1f, 0.1f, 0.9f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.2f, 0.2f, 0.2f, 0.9f);
    style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.15f, 0.15f, 0.15f, 0.9f);
    
    // Titles
    style.Colors[ImGuiCol_TitleBg] = bg_popup;
    style.Colors[ImGuiCol_TitleBgActive] = bg_popup;
    style.Colors[ImGuiCol_TitleBgCollapsed] = bg_popup;
    
    // Scrollbar
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.05f, 0.05f, 0.05f, 0.9f);
    style.Colors[ImGuiCol_ScrollbarGrab] = accent;
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = accent_hover;
    style.Colors[ImGuiCol_ScrollbarGrabActive] = accent_hover;
    
    // Checkboxes
    style.Colors[ImGuiCol_CheckMark] = text_primary;
    
    // Sliders
    style.Colors[ImGuiCol_SliderGrab] = accent;
    style.Colors[ImGuiCol_SliderGrabActive] = accent_hover;
    
    // Separators
    style.Colors[ImGuiCol_Separator] = ImVec4(0.3f, 0.3f, 0.3f, 0.5f);
    style.Colors[ImGuiCol_SeparatorHovered] = accent_hover;
    style.Colors[ImGuiCol_SeparatorActive] = accent_hover;
    
    // Resize grip
    style.Colors[ImGuiCol_ResizeGrip] = accent;
    style.Colors[ImGuiCol_ResizeGripHovered] = accent_hover;
    style.Colors[ImGuiCol_ResizeGripActive] = accent_hover;
    
    // Tabs
    style.Colors[ImGuiCol_Tab] = accent;
    style.Colors[ImGuiCol_TabHovered] = accent_hover;
    style.Colors[ImGuiCol_TabActive] = accent_hover;
    style.Colors[ImGuiCol_TabUnfocused] = ImVec4(0.1f, 0.1f, 0.1f, 0.9f);
    style.Colors[ImGuiCol_TabUnfocusedActive] = accent;
    
    // Rounding
    style.FrameRounding = 4.0f;
    style.WindowRounding = 8.0f;
    style.ChildRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 4.0f;
    style.ScrollbarRounding = 4.0f;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    DNAMessengerApp app;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        app.render();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0x15/255.0f, 0x17/255.0f, 0x19/255.0f, 1.0f); // #151719
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
