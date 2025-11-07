// DNA Messenger - ImGui GUI
// Modern, lightweight, cross-platform messenger interface
// UI SKETCH MODE - Backend integration disabled for UI development

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "modal_helper.h"
#include "font_awesome.h"
#include "theme_colors.h"
#include <GLFW/glfw3.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cstdlib>

#ifndef _WIN32
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <windows.h>
#include <direct.h>
#endif

// Comment out backend includes for UI sketch mode
/*
extern "C" {
#include "../dna_api.h"
#include "../messenger_p2p.h"
#include "../messenger.h"
#include "../wallet.h"
#include "../messenger/keyserver_register.h"
#include "../bip39.h"
}
*/

// Global theme variable
int g_current_theme = 0; // 0 = DNA, 1 = Club

// Apply theme colors to ImGui
void ApplyTheme(int theme) {
    ImGuiStyle& style = ImGui::GetStyle();
    
    if (theme == 0) { // DNA Theme
        style.Colors[ImGuiCol_Text] = DNATheme::Text();
        style.Colors[ImGuiCol_TextDisabled] = DNATheme::TextDisabled();
        style.Colors[ImGuiCol_WindowBg] = DNATheme::Background();
        style.Colors[ImGuiCol_ChildBg] = DNATheme::Background();
        style.Colors[ImGuiCol_PopupBg] = DNATheme::Background();
        style.Colors[ImGuiCol_Border] = DNATheme::Border();
        style.Colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
        style.Colors[ImGuiCol_FrameBg] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_FrameBgHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_FrameBgActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_TitleBg] = DNATheme::Background();
        style.Colors[ImGuiCol_TitleBgActive] = DNATheme::Background();
        style.Colors[ImGuiCol_TitleBgCollapsed] = DNATheme::Background();
        style.Colors[ImGuiCol_MenuBarBg] = DNATheme::Background();
        style.Colors[ImGuiCol_ScrollbarBg] = DNATheme::Background();
        style.Colors[ImGuiCol_ScrollbarGrab] = DNATheme::Text();
        style.Colors[ImGuiCol_ScrollbarGrabHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_ScrollbarGrabActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_CheckMark] = DNATheme::Background(); // Dark background for inner circle
        style.Colors[ImGuiCol_SliderGrab] = DNATheme::Text();
        style.Colors[ImGuiCol_SliderGrabActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Button] = DNATheme::Text();
        style.Colors[ImGuiCol_ButtonHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_ButtonActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Header] = DNATheme::Text();
        style.Colors[ImGuiCol_HeaderHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_HeaderActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Separator] = DNATheme::Separator();
        style.Colors[ImGuiCol_SeparatorHovered] = DNATheme::Text();
        style.Colors[ImGuiCol_SeparatorActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_ResizeGrip] = DNATheme::Text();
        style.Colors[ImGuiCol_ResizeGripHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_ResizeGripActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Tab] = DNATheme::Background();
        style.Colors[ImGuiCol_TabHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TabSelected] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_TabSelectedOverline] = DNATheme::Text();
        style.Colors[ImGuiCol_TabDimmed] = DNATheme::Background();
        style.Colors[ImGuiCol_TabDimmedSelected] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TabDimmedSelectedOverline] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_PlotLines] = DNATheme::Text();
        style.Colors[ImGuiCol_PlotLinesHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_PlotHistogram] = DNATheme::Text();
        style.Colors[ImGuiCol_PlotHistogramHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TableHeaderBg] = DNATheme::Background();
        style.Colors[ImGuiCol_TableBorderStrong] = DNATheme::Border();
        style.Colors[ImGuiCol_TableBorderLight] = DNATheme::Border();
        style.Colors[ImGuiCol_TableRowBg] = DNATheme::Background();
        style.Colors[ImGuiCol_TableRowBgAlt] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TextSelectedBg] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_DragDropTarget] = DNATheme::Text();
        style.Colors[ImGuiCol_NavHighlight] = DNATheme::Text();
        style.Colors[ImGuiCol_NavWindowingHighlight] = DNATheme::Text();
        style.Colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.2f);
        style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.35f);
    } else { // Club Theme
        style.Colors[ImGuiCol_Text] = ClubTheme::Text();
        style.Colors[ImGuiCol_TextDisabled] = ClubTheme::TextDisabled();
        style.Colors[ImGuiCol_WindowBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_ChildBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_PopupBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_Border] = ClubTheme::Border();
        style.Colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
        style.Colors[ImGuiCol_FrameBg] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_FrameBgHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_FrameBgActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_TitleBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_TitleBgActive] = ClubTheme::Background();
        style.Colors[ImGuiCol_TitleBgCollapsed] = ClubTheme::Background();
        style.Colors[ImGuiCol_MenuBarBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_ScrollbarBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_ScrollbarGrab] = ClubTheme::Text();
        style.Colors[ImGuiCol_ScrollbarGrabHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_ScrollbarGrabActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_CheckMark] = ClubTheme::Background(); // Dark background for inner circle
        style.Colors[ImGuiCol_SliderGrab] = ClubTheme::Text();
        style.Colors[ImGuiCol_SliderGrabActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Button] = ClubTheme::Text();
        style.Colors[ImGuiCol_ButtonHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_ButtonActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Header] = ClubTheme::Text();
        style.Colors[ImGuiCol_HeaderHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_HeaderActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Separator] = ClubTheme::Separator();
        style.Colors[ImGuiCol_SeparatorHovered] = ClubTheme::Text();
        style.Colors[ImGuiCol_SeparatorActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_ResizeGrip] = ClubTheme::Text();
        style.Colors[ImGuiCol_ResizeGripHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_ResizeGripActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Tab] = ClubTheme::Background();
        style.Colors[ImGuiCol_TabHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TabSelected] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_TabSelectedOverline] = ClubTheme::Text();
        style.Colors[ImGuiCol_TabDimmed] = ClubTheme::Background();
        style.Colors[ImGuiCol_TabDimmedSelected] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TabDimmedSelectedOverline] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_PlotLines] = ClubTheme::Text();
        style.Colors[ImGuiCol_PlotLinesHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_PlotHistogram] = ClubTheme::Text();
        style.Colors[ImGuiCol_PlotHistogramHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TableHeaderBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_TableBorderStrong] = ClubTheme::Border();
        style.Colors[ImGuiCol_TableBorderLight] = ClubTheme::Border();
        style.Colors[ImGuiCol_TableRowBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_TableRowBgAlt] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TextSelectedBg] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_DragDropTarget] = ClubTheme::Text();
        style.Colors[ImGuiCol_NavHighlight] = ClubTheme::Text();
        style.Colors[ImGuiCol_NavWindowingHighlight] = ClubTheme::Text();
        style.Colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.2f);
        style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.35f);
    }
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

// Helper function for modal/dialog buttons with dark text
inline bool ButtonDark(const char* label, const ImVec2& size = ImVec2(0, 0)) {
    ImVec4 btn_color, hover_color, active_color, text_color;
    
    if (g_current_theme == 0) { // DNA Theme
        btn_color = DNATheme::Text();
        hover_color = ImVec4(0.0f, 0.9f, 0.7f, 1.0f);
        active_color = ImVec4(0.0f, 0.8f, 0.6f, 1.0f);
        text_color = DNATheme::SelectedText();
    } else { // Club Theme
        btn_color = ClubTheme::Text();
        hover_color = ImVec4(0.876f, 0.371f, 0.104f, 1.0f);
        active_color = ImVec4(0.776f, 0.271f, 0.004f, 1.0f);
        text_color = ClubTheme::SelectedText();
    }
    
    ImGui::PushStyleColor(ImGuiCol_Button, btn_color);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hover_color);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, active_color);
    ImGui::PushStyleColor(ImGuiCol_Text, text_color);
    bool result = ImGui::Button(label, size);
    ImGui::PopStyleColor(4);
    return result;
}

// Helper function for themed main buttons
inline bool ThemedButton(const char* label, const ImVec2& size = ImVec2(0, 0), bool is_active = false) {
    ImVec4 btn_color, hover_color, active_color, text_color, text_bg;
    
    if (g_current_theme == 0) { // DNA Theme
        btn_color = DNATheme::Text();
        hover_color = DNATheme::ButtonHover();
        active_color = DNATheme::ButtonActive();
        text_color = DNATheme::SelectedText();
        text_bg = DNATheme::Background();
    } else { // Club Theme
        btn_color = ClubTheme::Text();
        hover_color = ClubTheme::ButtonHover();
        active_color = ClubTheme::ButtonActive();
        text_color = ClubTheme::SelectedText();
        text_bg = ClubTheme::Background();
    }
    
    if (is_active) {
        // Active state: same as ButtonActive (slightly darker than hover)
        ImGui::PushStyleColor(ImGuiCol_Button, active_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, active_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, active_color);
    } else {
        ImGui::PushStyleColor(ImGuiCol_Button, btn_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hover_color);
        ImGui::PushStyleColor(ImGuiCol_ButtonActive, active_color);
    }
    
    ImGui::PushStyleColor(ImGuiCol_Text, text_color);
    bool result = ImGui::Button(label, size);
    ImGui::PopStyleColor(4);
    return result;
}

class DNAMessengerApp {
public:
    DNAMessengerApp() {
        current_view = VIEW_CONTACTS;
        selected_contact = -1;
        show_wallet = false;
        show_identity_selection = true;
        identity_loaded = false;
        selected_identity_idx = -1;
        create_identity_step = STEP_NAME;
        seed_confirmed = false;
        seed_copied = false;
        seed_copied_timer = 0.0f;
        memset(new_identity_name, 0, sizeof(new_identity_name));
        memset(generated_mnemonic, 0, sizeof(generated_mnemonic));
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
        
        // Add global padding
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 20));
        
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
        ImGui::PopStyleVar(); // Pop WindowPadding
    }

private:
    enum View {
        VIEW_CONTACTS,
        VIEW_CHAT,
        VIEW_WALLET,
        VIEW_SETTINGS
    };
    
    enum CreateIdentityStep {
        STEP_NAME,
        STEP_SEED_PHRASE,
        STEP_CREATING
    };

    View current_view;
    int selected_contact;
    bool show_wallet;
    bool show_identity_selection;
    bool identity_loaded;
    int selected_identity_idx;
    CreateIdentityStep create_identity_step;
    char generated_mnemonic[512];
    bool seed_confirmed;
    bool seed_copied;
    float seed_copied_timer;
    
    std::vector<Contact> contacts;
    std::map<int, std::vector<Message>> contact_messages;  // Per-contact message history
    std::vector<std::string> identities;
    std::string current_identity;
    char message_input[1024] = "";
    char new_identity_name[128];
    
    void renderIdentitySelection() {
        ImGuiIO& io = ImGui::GetIO();
        bool is_mobile = io.DisplaySize.x < 600.0f;
        
        // Open the modal on first render
        static bool first_render = true;
        if (first_render) {
            ImGui::OpenPopup("DNA Messenger - Select Identity");
            first_render = false;
        }
        
        // Set size before modal
        ImGui::SetNextWindowSize(ImVec2(is_mobile ? io.DisplaySize.x * 0.9f : 500, is_mobile ? io.DisplaySize.y * 0.9f : 500));
        
        if (CenteredModal::Begin("DNA Messenger - Select Identity", nullptr, ImGuiWindowFlags_NoResize)) {
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
                
                float item_height = is_mobile ? 50 : 35;
                ImVec2 text_size = ImGui::CalcTextSize(identities[i].c_str());
                float text_offset_y = (item_height - text_size.y) * 0.5f;
                
                // Custom color handling for hover and selection
                ImVec4 text_color = (g_current_theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                ImVec4 bg_color = (g_current_theme == 0) ? DNATheme::Background() : ClubTheme::Background();
                
                ImVec2 pos = ImGui::GetCursorScreenPos();
                ImVec2 size = ImVec2(ImGui::GetContentRegionAvail().x, item_height);
                
                // Check hover
                bool hovered = ImGui::IsMouseHoveringRect(pos, ImVec2(pos.x + size.x, pos.y + size.y));
                
                if (hovered) {
                    bg_color = (g_current_theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                    text_color = (g_current_theme == 0) ? DNATheme::Background() : ClubTheme::Background();
                }
                
                if (selected) {
                    bg_color = (g_current_theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                    text_color = (g_current_theme == 0) ? DNATheme::Background() : ClubTheme::Background();
                }
                
                // Draw background
                if (selected || hovered) {
                    ImGui::GetWindowDrawList()->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), ImGui::GetColorU32(bg_color));
                }
                
                // Draw text centered vertically with left padding
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + text_offset_y);
                ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 10.0f);
                ImGui::PushStyleColor(ImGuiCol_Text, text_color);
                ImGui::Text("%s", identities[i].c_str());
                ImGui::PopStyleColor();
                
                // Move cursor back and render invisible button for click detection
                ImGui::SetCursorScreenPos(pos);
                if (ImGui::InvisibleButton(identities[i].c_str(), size)) {
                    if (selected_identity_idx == (int)i) {
                        selected_identity_idx = -1;
                    } else {
                        selected_identity_idx = i;
                    }
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
        if (ButtonDark(ICON_FA_USER " Select Identity", ImVec2(-1, btn_height))) {
            if (selected_identity_idx >= 0 && selected_identity_idx < (int)identities.size()) {
                current_identity = identities[selected_identity_idx];
                loadIdentity(current_identity);
            }
        }
        ImGui::EndDisabled();
        
        // Create new button
        if (ButtonDark(ICON_FA_PLUS " Create New Identity", ImVec2(-1, btn_height))) {
            create_identity_step = STEP_NAME;
            seed_confirmed = false;
            memset(new_identity_name, 0, sizeof(new_identity_name));
            memset(generated_mnemonic, 0, sizeof(generated_mnemonic));
            ImGui::OpenPopup("Create New Identity");
        }
        
            // Create identity popup - multi-step wizard (using CenteredModal helper)
            if (CenteredModal::Begin("Create New Identity")) {
                if (create_identity_step == STEP_NAME) {
                    renderCreateIdentityStep1();
                } else if (create_identity_step == STEP_SEED_PHRASE) {
                    renderCreateIdentityStep2();
                } else if (create_identity_step == STEP_CREATING) {
                    renderCreateIdentityStep3();
                }
                
                CenteredModal::End();
            }
            
            CenteredModal::End(); // End identity selection modal
        }
    }
    
    void scanIdentities() {
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
    
    // Input filter callback for identity name (alphanumeric + underscore only)
    static int IdentityNameInputFilter(ImGuiInputTextCallbackData* data) {
        if (data->EventChar < 256) {
            char c = (char)data->EventChar;
            if ((c >= 'a' && c <= 'z') || 
                (c >= 'A' && c <= 'Z') || 
                (c >= '0' && c <= '9') || 
                c == '_') {
                return 0; // Accept
            }
        }
        return 1; // Reject
    }
    
    void renderCreateIdentityStep1() {
        // Step 1: Enter identity name
        ImGui::Text("Step 1: Choose Your Identity Name");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        ImGui::TextWrapped("Your identity name is your username in DNA Messenger.");
        ImGui::TextWrapped("Requirements: 3-20 characters, letters/numbers/underscore only");
        ImGui::Spacing();
        
        // Auto-focus input when step 1 is active
        if (create_identity_step == STEP_NAME && strlen(new_identity_name) == 0) {
            ImGui::SetKeyboardFocusHere();
        }
        
        bool enter_pressed = ImGui::InputText("##IdentityName", new_identity_name, sizeof(new_identity_name), 
                        ImGuiInputTextFlags_CallbackCharFilter | ImGuiInputTextFlags_EnterReturnsTrue, IdentityNameInputFilter);
        
        // Validate identity name
        size_t name_len = strlen(new_identity_name);
        bool name_valid = true;
        std::string error_msg;
        
        if (name_len > 0) {
            // First check for invalid characters (highest priority)
            char invalid_char = '\0';
            for (size_t i = 0; i < name_len; i++) {
                char c = new_identity_name[i];
                if (!((c >= 'a' && c <= 'z') || 
                      (c >= 'A' && c <= 'Z') || 
                      (c >= '0' && c <= '9') || 
                      c == '_')) {
                    name_valid = false;
                    invalid_char = c;
                    char buf[64];
                    snprintf(buf, sizeof(buf), "Invalid character \"%c\"", c);
                    error_msg = buf;
                    break;
                }
            }
            
            // Then check length only if characters are valid
            if (name_valid) {
                if (name_len < 3) {
                    name_valid = false;
                    error_msg = "Too short (minimum 3 characters)";
                } else if (name_len > 20) {
                    name_valid = false;
                    error_msg = "Too long (maximum 20 characters)";
                }
            }
        } else {
            name_valid = false;
        }
        
        // Show validation feedback
        if (name_len > 0 && !name_valid) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f)); // Red
            ImGui::TextWrapped("✗ %s", error_msg.c_str());
            ImGui::PopStyleColor();
        } else if (name_len > 0 && name_valid) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 1.0f, 0.3f, 1.0f)); // Green
            ImGui::Text("✓ Valid identity name");
            ImGui::PopStyleColor();
        }
        
        ImGui::Spacing();
        ImGui::Spacing();
        
        // Center buttons
        float button_width = 120.0f;
        float spacing = 10.0f;
        float total_width = button_width * 2 + spacing;
        float offset = (ImGui::GetContentRegionAvail().x - total_width) * 0.5f;
        
        if (offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + offset);
        
        ImGui::BeginDisabled(!name_valid || name_len == 0);
        if (ButtonDark("Next", ImVec2(button_width, 40)) || (enter_pressed && name_valid && name_len > 0)) {
            // Generate mock seed phrase for UI sketch mode
            snprintf(generated_mnemonic, sizeof(generated_mnemonic), 
                "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual");
            create_identity_step = STEP_SEED_PHRASE;
        }
        ImGui::EndDisabled();
        
        ImGui::SameLine();
        if (ButtonDark("Cancel", ImVec2(button_width, 40))) {
            ImGui::CloseCurrentPopup();
        }
    }
    
    void renderCreateIdentityStep2() {
        // Step 2: Display and confirm seed phrase
        ImGui::Text("Step 2: Your Recovery Seed Phrase");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.3f, 0.3f, 1.0f)); // Red warning
        ImGui::TextWrapped("IMPORTANT: Write down these 24 words in order!");
        ImGui::TextWrapped("This is the ONLY way to recover your identity.");
        ImGui::PopStyleColor();
        ImGui::Spacing();
        
        // Copy button - full width
        if (ButtonDark(ICON_FA_COPY " Copy All Words", ImVec2(-1, 40))) {
            ImGui::SetClipboardText(generated_mnemonic);
            seed_copied = true;
            seed_copied_timer = 3.0f; // Show message for 3 seconds
        }
        
        ImGui::Spacing();
        
        // Display seed phrase in a bordered box with proper alignment
        ImGui::BeginChild("SeedPhraseDisplay", ImVec2(0, 250), true, ImGuiWindowFlags_NoScrollbar);
        
        // Split mnemonic into words
        char* mnemonic_copy = strdup(generated_mnemonic);
        char* words[24];
        int word_count = 0;
        char* token = strtok(mnemonic_copy, " ");
        while (token != nullptr && word_count < 24) {
            words[word_count++] = token;
            token = strtok(nullptr, " ");
        }
        
        // Display in 2 columns of 12 words each for better readability
        ImGui::Columns(2, nullptr, false);
        
        for (int i = 0; i < word_count; i++) {
            // Format: " 1. word      "
            char label[32];
            snprintf(label, sizeof(label), "%2d. %-14s", i + 1, words[i]);
            ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.8f, 1.0f), "%s", label);
            
            // Switch to second column after 12 words
            if (i == 11) {
                ImGui::NextColumn();
            }
        }
        
        ImGui::Columns(1);
        
        free(mnemonic_copy);
        
        ImGui::EndChild();
        
        ImGui::Spacing();
        ImGui::Checkbox("I have written down my 24-word seed phrase securely", &seed_confirmed);
        ImGui::Spacing();
        
        // Show success message if recently copied (above buttons)
        if (seed_copied && seed_copied_timer > 0.0f) {
            ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 1.0f, 0.3f, 1.0f)); // Green
            ImGui::Text("✓ Words copied to clipboard!");
            ImGui::PopStyleColor();
            seed_copied_timer -= ImGui::GetIO().DeltaTime;
            if (seed_copied_timer <= 0.0f) {
                seed_copied = false;
            }
        }
        
        ImGui::Spacing();
        
        // Center buttons
        float button_width = 120.0f;
        float spacing = 10.0f;
        float total_width = button_width * 2 + spacing;
        float offset = (ImGui::GetContentRegionAvail().x - total_width) * 0.5f;
        
        if (offset > 0) ImGui::SetCursorPosX(ImGui::GetCursorPosX() + offset);
        
        if (ButtonDark("Back", ImVec2(button_width, 40))) {
            create_identity_step = STEP_NAME;
        }
        ImGui::SameLine();
        
        ImGui::BeginDisabled(!seed_confirmed);
        if (ButtonDark("Create", ImVec2(button_width, 40))) {
            create_identity_step = STEP_CREATING;
            createIdentityWithSeed(new_identity_name, generated_mnemonic);
        }
        ImGui::EndDisabled();
    }
    
    void renderCreateIdentityStep3() {
        // Step 3: Creating identity (progress)
        ImGui::Text("Creating Your Identity...");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        ImGui::TextWrapped("Generating cryptographic keys and registering to keyserver...");
        ImGui::Spacing();
        
        // Simple progress indicator (spinner would be better but this works)
        static float progress = 0.0f;
        progress += 0.01f;
        if (progress > 1.0f) progress = 0.0f;
        
        ImGui::ProgressBar(progress, ImVec2(-1, 0));
        
        // This step auto-closes when createIdentityWithSeed completes
    }
    
    void createIdentityWithSeed(const char* name, const char* mnemonic) {
        // UI SKETCH MODE - Mock identity creation
        printf("[SKETCH MODE] Creating identity: %s\n", name);
        printf("[SKETCH MODE] Mnemonic: %s\n", mnemonic);
        
        // Simulate success
        identities.push_back(name);
        current_identity = name;
        identity_loaded = true;
        show_identity_selection = false;
        
        // Reset and close
        memset(new_identity_name, 0, sizeof(new_identity_name));
        memset(generated_mnemonic, 0, sizeof(generated_mnemonic));
        seed_confirmed = false;
        ImGui::CloseCurrentPopup();
        
        printf("[SKETCH MODE] Identity created successfully\n");
    }
    
    void loadIdentity(const std::string& identity) {
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
        contact_messages[0].push_back({contacts[0].name, "Nice! Post-quantum crypto is the future 🚀", "Today 10:33 AM", false});
        contact_messages[0].push_back({"Me", "Absolutely! Kyber1024 + Dilithium5", "Today 10:35 AM", true});
        contact_messages[0].push_back({contacts[0].name, "Can't wait to try it out!", "Today 10:36 AM", false});
        
        // Mock message history for second contact
        contact_messages[1].push_back({contacts[1].name, "Are you available tomorrow?", "Yesterday 3:45 PM", false});
        contact_messages[1].push_back({"Me", "Yes, what's up?", "Yesterday 4:12 PM", true});
        contact_messages[1].push_back({contacts[1].name, "Let's discuss the new features", "Yesterday 4:15 PM", false});
        
        printf("[SKETCH MODE] Loaded %zu mock contacts (sorted: online first)\n", contacts.size());
        
        identity_loaded = true;
        show_identity_selection = false;
        
        printf("[SKETCH MODE] Identity loaded successfully!\n");
    }
    
    void renderMobileLayout() {
        ImGuiIO& io = ImGui::GetIO();
        float screen_height = io.DisplaySize.y;
        float bottom_nav_height = 60.0f;
        
        // Content area (full screen minus bottom nav) - use full width
        ImGui::BeginChild("MobileContent", ImVec2(-1, -bottom_nav_height), false, ImGuiWindowFlags_NoScrollbar);
        
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
        if (ThemedButton(ICON_FA_COMMENTS "\nChats", ImVec2(btn_width, 60), current_view == VIEW_CONTACTS)) {
            current_view = VIEW_CONTACTS;
        }
        
        ImGui::SameLine();
        
        // Wallet button
        if (ThemedButton(ICON_FA_WALLET "\nWallet", ImVec2(btn_width, 60), current_view == VIEW_WALLET)) {
            current_view = VIEW_WALLET;
            selected_contact = -1;
        }
        
        ImGui::SameLine();
        
        // Settings button
        if (ThemedButton(ICON_FA_COG "\nSettings", ImVec2(btn_width, 60), current_view == VIEW_SETTINGS)) {
            current_view = VIEW_SETTINGS;
            selected_contact = -1;
        }
        
        ImGui::SameLine();
        
        // Profile button (placeholder)
        if (ThemedButton(ICON_FA_USER "\nProfile", ImVec2(btn_width, 60), false)) {
            // TODO: Profile view
        }
        
        ImGui::PopStyleVar(2);
    }
    
    void renderContactsList() {
        ImGuiIO& io = ImGui::GetIO();
        
        // Get full available width before any child windows
        float full_width = ImGui::GetContentRegionAvail().x;
        printf("[DEBUG] ContactsList available width: %.1f, screen width: %.1f\n", full_width, io.DisplaySize.x);
        
        // Top bar with title and add button
        ImGui::BeginChild("ContactsHeader", ImVec2(full_width, 60), true, ImGuiWindowFlags_NoScrollbar);
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10);
        
        ImGui::SetWindowFontScale(1.5f);
        ImGui::Text("  DNA Messenger");
        ImGui::SetWindowFontScale(1.0f);
        
        ImGui::SameLine(io.DisplaySize.x - 60);
        if (ButtonDark(ICON_FA_PLUS, ImVec2(50, 40))) {
            // TODO: Add contact dialog
        }
        
        ImGui::EndChild();
        
        // Contact list (large touch targets)
        ImGui::BeginChild("ContactsScrollArea", ImVec2(full_width, 0), false);
        
        for (size_t i = 0; i < contacts.size(); i++) {
            ImGui::PushID(i);
            
            // Get button width
            float button_width = ImGui::GetContentRegionAvail().x;
            if (i == 0) {
                printf("[DEBUG] Contact button width: %.1f\n", button_width);
            }
            
            // Large touch-friendly buttons (80px height)
            bool selected = (int)i == selected_contact;
            if (selected) {
                ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.0f, 0.8f, 0.8f, 0.3f));
            }
            
            if (ButtonDark("##contact", ImVec2(button_width, 80))) {
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
        // Push border color before creating child
        ImVec4 border_col = (g_current_theme == 0) ? DNATheme::Separator() : ClubTheme::Separator();
        ImGui::PushStyleColor(ImGuiCol_Border, border_col);
        
        ImGui::BeginChild("Sidebar", ImVec2(250, 0), true, ImGuiWindowFlags_NoScrollbar);
        
        ImGui::Text("DNA Messenger");
        ImGui::Separator();
        
        // Navigation buttons (40px each)
        if (ThemedButton(ICON_FA_COMMENTS " Chat", ImVec2(-1, 40), current_view == VIEW_CONTACTS || current_view == VIEW_CHAT)) {
            current_view = VIEW_CONTACTS;
        }
        if (ThemedButton(ICON_FA_WALLET " Wallet", ImVec2(-1, 40), current_view == VIEW_WALLET)) {
            current_view = VIEW_WALLET;
        }
        if (ThemedButton(ICON_FA_COG " Settings", ImVec2(-1, 40), current_view == VIEW_SETTINGS)) {
            current_view = VIEW_SETTINGS;
        }
        
        ImGui::Separator();
        ImGui::Text("Contacts");
        ImGui::Separator();
        
        // Contact list - use remaining space minus add button height
        float add_button_height = 40.0f;
        float available_height = ImGui::GetContentRegionAvail().y - add_button_height - ImGui::GetStyle().ItemSpacing.y;
        
        ImGui::BeginChild("ContactList", ImVec2(0, available_height), false);
        
        float list_width = ImGui::GetContentRegionAvail().x;
        for (size_t i = 0; i < contacts.size(); i++) {
            ImGui::PushID(i);
            
            float item_height = 30;
            bool selected = (selected_contact == (int)i);
            
            // Use invisible button for interaction
            ImVec2 cursor_screen_pos = ImGui::GetCursorScreenPos();
            bool clicked = ImGui::InvisibleButton("##contact", ImVec2(list_width, item_height));
            bool hovered = ImGui::IsItemHovered();
            
            if (clicked) {
                selected_contact = i;
                current_view = VIEW_CHAT;
            }
            
            // Draw background
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            ImVec2 rect_min = cursor_screen_pos;
            ImVec2 rect_max = ImVec2(cursor_screen_pos.x + list_width, cursor_screen_pos.y + item_height);
            
            if (selected) {
                ImVec4 col = (g_current_theme == 0) ? DNATheme::ButtonActive() : ClubTheme::ButtonActive();
                ImU32 bg_color = IM_COL32((int)(col.x * 255), (int)(col.y * 255), (int)(col.z * 255), 255);
                draw_list->AddRectFilled(rect_min, rect_max, bg_color);
            } else if (hovered) {
                ImVec4 col = (g_current_theme == 0) ? DNATheme::ButtonHover() : ClubTheme::ButtonHover();
                ImU32 bg_color = IM_COL32((int)(col.x * 255), (int)(col.y * 255), (int)(col.z * 255), 255);
                draw_list->AddRectFilled(rect_min, rect_max, bg_color);
            }
            
            // Format: "✓ Name" or "✗ Name" with colored icons
            const char* icon = contacts[i].is_online ? ICON_FA_CHECK_CIRCLE : ICON_FA_TIMES_CIRCLE;
            
            char display_text[256];
            snprintf(display_text, sizeof(display_text), "%s   %s", icon, contacts[i].name.c_str());
            
            // Center text vertically
            ImVec2 text_size = ImGui::CalcTextSize(display_text);
            float text_offset_y = (item_height - text_size.y) * 0.5f;
            ImVec2 text_pos = ImVec2(cursor_screen_pos.x + 8, cursor_screen_pos.y + text_offset_y);
            ImU32 text_color;
            if (selected || hovered) {
                // Use theme background color when selected or hovered
                ImVec4 bg_col = (g_current_theme == 0) ? DNATheme::Background() : ClubTheme::Background();
                text_color = IM_COL32((int)(bg_col.x * 255), (int)(bg_col.y * 255), (int)(bg_col.z * 255), 255);
            } else {
                // Normal colors when not selected - use theme colors
                if (contacts[i].is_online) {
                    ImVec4 text_col = (g_current_theme == 0) ? DNATheme::Text() : ClubTheme::Text();
                    text_color = IM_COL32((int)(text_col.x * 255), (int)(text_col.y * 255), (int)(text_col.z * 255), 255);
                } else {
                    text_color = IM_COL32(100, 100, 100, 255);
                }
            }
            draw_list->AddText(text_pos, text_color, display_text);
            
            ImGui::PopID();
        }
        
        ImGui::EndChild(); // ContactList
        
        // Add contact button at bottom (40px to match main buttons)
        float button_width = ImGui::GetContentRegionAvail().x;
        if (ThemedButton(ICON_FA_PLUS " Add Contact", ImVec2(button_width, add_button_height), false)) {
            // TODO: Open add contact dialog
        }
        
        ImGui::EndChild(); // Sidebar
        
        ImGui::PopStyleColor(); // Border
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
            if (ButtonDark(ICON_FA_ARROW_LEFT " Back", ImVec2(100, 40))) {
                current_view = VIEW_CONTACTS;
                selected_contact = -1;
            }
            ImGui::SameLine();
        }
        
        // Style contact name same as in contact list
        const char* status_icon = contact.is_online ? ICON_FA_CHECK : ICON_FA_TIMES;
        ImVec4 icon_color;
        if (contact.is_online) {
            icon_color = (g_current_theme == 0) ? DNATheme::Text() : ClubTheme::Text();
        } else {
            icon_color = ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
        }
        
        // Center text vertically in header
        float text_size_y = ImGui::CalcTextSize(contact.name.c_str()).y;
        float text_offset_y = (header_height - text_size_y) * 0.5f;
        ImGui::SetCursorPosY(text_offset_y);
        
        ImGui::TextColored(icon_color, "%s", status_icon);
        ImGui::SameLine();
        
        ImVec4 text_col = (g_current_theme == 0) ? DNATheme::Text() : ClubTheme::Text();
        if (!contact.is_online) {
            text_col = ImVec4(0.8f, 0.8f, 0.8f, 1.0f);
        }
        ImGui::TextColored(text_col, "%s", contact.name.c_str());
        
        ImGui::EndChild();
        
        // Message area
        float input_height = is_mobile ? 100.0f : 80.0f;
        ImGui::BeginChild("MessageArea", ImVec2(0, -input_height), true);
        
        // Get messages for current contact
        std::vector<Message>& messages = contact_messages[selected_contact];
        
        for (size_t i = 0; i < messages.size(); i++) {
            const auto& msg = messages[i];
            
            // Calculate bubble width based on current window size
            float available_width = ImGui::GetContentRegionAvail().x;
            float bubble_width = available_width * 0.65f;  // 65% of available width
            
            // All bubbles aligned left (Telegram-style)
            
            // Draw bubble background with proper padding (theme-aware)
            ImVec4 base_color = (g_current_theme == 0) ? DNATheme::Text() : ClubTheme::Text();
            
            // Recipient bubble: much lighter (0.12 opacity)
            // Own bubble: normal opacity (0.25)
            ImVec4 bg_color;
            if (msg.is_outgoing) {
                bg_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.25f);
            } else {
                bg_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.12f);
            }
            
            ImGui::PushStyleColor(ImGuiCol_ChildBg, bg_color);
            ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0, 0, 0, 0)); // No border
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 0.0f); // Square corners
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(30.0f, 30.0f));
            
            char bubble_id[32];
            snprintf(bubble_id, sizeof(bubble_id), "bubble%zu", i);
            
            // Calculate padding and dimensions
            float padding_horizontal = 15.0f;
            float padding_vertical = 12.0f;
            float content_width = bubble_width - (padding_horizontal * 2);
            
            ImVec2 text_size = ImGui::CalcTextSize(msg.content.c_str(), NULL, false, content_width);
            
            float bubble_height = text_size.y + (padding_vertical * 2);
            
            ImGui::BeginChild(bubble_id, ImVec2(bubble_width, bubble_height), false, 
                ImGuiWindowFlags_NoScrollbar);
            
            // Apply padding
            ImGui::SetCursorPos(ImVec2(padding_horizontal, padding_vertical));
            
            // Message text with wrapping
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + content_width);
            ImGui::TextWrapped("%s", msg.content.c_str());
            ImGui::PopTextWrapPos();
            
            ImGui::EndChild();
            
            // Get bubble position for arrow (AFTER EndChild)
            ImVec2 bubble_min = ImGui::GetItemRectMin();
            ImVec2 bubble_max = ImGui::GetItemRectMax();
            
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor(2);
            
            // Draw triangle arrow pointing DOWN from bubble to username
            ImDrawList* draw_list = ImGui::GetWindowDrawList();
            ImVec4 arrow_color;
            if (msg.is_outgoing) {
                arrow_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.25f);
            } else {
                arrow_color = ImVec4(base_color.x, base_color.y, base_color.z, 0.12f);
            }
            ImU32 arrow_col = ImGui::ColorConvertFloat4ToU32(arrow_color);
            
            // Triangle points: pointing DOWN from bubble to username
            float arrow_x = bubble_min.x + 20.0f; // 20px from left edge
            float arrow_top = bubble_max.y; // Bottom of bubble
            float arrow_bottom = bubble_max.y + 10.0f; // Point of arrow extends down
            
            ImVec2 p1(arrow_x, arrow_bottom);           // Bottom point (pointing down)
            ImVec2 p2(arrow_x - 8.0f, arrow_top);       // Top left (at bubble bottom)
            ImVec2 p3(arrow_x + 8.0f, arrow_top);       // Top right (at bubble bottom)
            
            draw_list->AddTriangleFilled(p1, p2, p3, arrow_col);
            
            // Sender name and timestamp BELOW the arrow (theme-aware)
            ImVec4 meta_color = (g_current_theme == 0) ? DNATheme::Text() : ClubTheme::Text();
            meta_color.w = 0.7f; // Slightly transparent
            
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 8.0f); // Space for arrow
            ImGui::PushStyleColor(ImGuiCol_Text, meta_color);
            const char* sender_label = msg.is_outgoing ? "You" : msg.sender.c_str();
            ImGui::Text("%s • %s", sender_label, msg.timestamp.c_str());
            ImGui::PopStyleColor();
            
            ImGui::Spacing();
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
            
            if (ButtonDark("Send", ImVec2(-1, 35))) {
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
            
            if (ButtonDark("Send", ImVec2(70, 60))) {
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
            if (ButtonDark(ICON_FA_PAPER_PLANE " Send Tokens", ImVec2(-1, btn_height))) {
                // TODO: Open send dialog
            }
            ImGui::Spacing();
            
            if (ButtonDark(ICON_FA_DOWNLOAD " Receive", ImVec2(-1, btn_height))) {
                // TODO: Show receive address
            }
            ImGui::Spacing();
            
            if (ButtonDark(ICON_FA_RECEIPT " Transaction History", ImVec2(-1, btn_height))) {
                // TODO: Show transaction history
            }
        } else {
            // Desktop: Side-by-side buttons
            ImGuiStyle& style = ImGui::GetStyle();
            float available_width = ImGui::GetContentRegionAvail().x;
            float spacing = style.ItemSpacing.x;
            float btn_width = (available_width - spacing * 2) / 3.0f;
            
            if (ButtonDark(ICON_FA_PAPER_PLANE " Send", ImVec2(btn_width, btn_height))) {
                // TODO: Open send dialog
            }
            ImGui::SameLine();
            
            if (ButtonDark(ICON_FA_DOWNLOAD " Receive", ImVec2(btn_width, btn_height))) {
                // TODO: Show receive address
            }
            ImGui::SameLine();
            
            if (ButtonDark(ICON_FA_RECEIPT " History", ImVec2(btn_width, btn_height))) {
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
        ImGui::Text(ICON_FA_COG " Settings");
        ImGui::SetWindowFontScale(1.0f);
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        
        // Theme selection
        ImGui::Text("Theme");
        ImGui::Spacing();
        
        int prev_theme = g_current_theme;
        
        if (is_mobile) {
            // Mobile: Full-width radio buttons with larger touch targets
            if (ImGui::RadioButton("cpunk.io (Cyan)##theme", g_current_theme == 0)) {
                g_current_theme = 0;
            }
            ImGui::Spacing();
            if (ImGui::RadioButton("cpunk.club (Orange)##theme", g_current_theme == 1)) {
                g_current_theme = 1;
            }
        } else {
            ImGui::RadioButton("cpunk.io (Cyan)", &g_current_theme, 0);
            ImGui::RadioButton("cpunk.club (Orange)", &g_current_theme, 1);
        }
        
        // Apply theme if changed
        if (prev_theme != g_current_theme) {
            ApplyTheme(g_current_theme);
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
            if (ButtonDark("🆕 Create New Identity", ImVec2(-1, btn_height))) {
                // TODO: Create identity dialog
            }
            ImGui::Spacing();
            
            if (ButtonDark("📥 Import Identity", ImVec2(-1, btn_height))) {
                // TODO: Import identity dialog
            }
        } else {
            if (ButtonDark("Create New Identity", ImVec2(200, btn_height))) {
                // TODO: Create identity dialog
            }
            ImGui::SameLine();
            if (ButtonDark("Import Identity", ImVec2(200, btn_height))) {
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

    // Set minimum window size for desktop
    glfwSetWindowSizeLimits(window, 1000, 600, GLFW_DONT_CARE, GLFW_DONT_CARE);

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

        // Load embedded fonts
    #include "fonts/NotoSans-Regular.h"
    #include "fonts/fa-solid-900.h"
    
    ImFontConfig config;
    config.MergeMode = false;
    config.FontDataOwnedByAtlas = false; // Don't let ImGui free our static embedded data
    
    // Default font (1.1x scale = 19.8px for base 18px)
    float base_size = 18.0f * 1.1f;
    io.Fonts->AddFontFromMemoryTTF((void*)NotoSans_Regular_ttf, sizeof(NotoSans_Regular_ttf), base_size, &config);
    
    // Merge Font Awesome icons
    config.MergeMode = true;
    config.GlyphMinAdvanceX = base_size;
    config.GlyphOffset = ImVec2(0, 2);
    config.FontDataOwnedByAtlas = false;
    static const ImWchar icon_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
    io.Fonts->AddFontFromMemoryTTF((void*)fa_solid_900_ttf, sizeof(fa_solid_900_ttf), base_size * 0.9f, &config, icon_ranges);

    ImGui::StyleColorsDark();
    
    // DNA Messenger styling
    ImGuiStyle& style = ImGui::GetStyle();
    
    // Rounding
    style.FrameRounding = 4.0f;
    style.WindowRounding = 8.0f;
    style.ChildRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 4.0f;
    style.ScrollbarRounding = 4.0f;
    
    // Selective borders: keep child borders (sidebar), remove others
    style.WindowBorderSize = 0.0f;
    style.FrameBorderSize = 0.0f;
    style.PopupBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;  // Keep this for sidebar
    
    // Apply initial theme (DNA theme by default)
    ApplyTheme(g_current_theme);

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
