#include "create_group_dialog.h"
#include "../modal_helper.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"

extern "C" {
    #include "../../messenger.h"
    #include "../../dht/shared/dht_groups.h"
}

#include <cstring>
#include <algorithm>

extern AppSettings g_app_settings;

namespace CreateGroupDialog {

void render(AppState& state) {
    if (!state.show_create_group_dialog) return;

    // Open popup on first show
    if (!ImGui::IsPopupOpen("Create Group")) {
        ImGui::OpenPopup("Create Group");
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = IsMobileLayout();

    if (CenteredModal::Begin("Create Group", &state.show_create_group_dialog,
                              ImGuiWindowFlags_NoResize, is_mobile, false, 500)) {

        // Group name input
        ImGui::Text(ICON_FA_USERS " Group Name");
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Text, g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text());
        ImGui::InputText("##GroupName", state.create_group_name_input,
                         sizeof(state.create_group_name_input));
        ImGui::PopStyleColor();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Members section
        ImGui::Text(ICON_FA_USER_PLUS " Select Members");
        ImGui::Spacing();

        // Member list (scrollable)
        ImGui::BeginChild("MemberList", ImVec2(0, 250), true);

        if (state.contacts.empty()) {
            ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::TextHint() : ClubTheme::TextHint(),
                             "No contacts available. Add contacts first.");
        } else {
            for (size_t i = 0; i < state.contacts.size(); i++) {
                ImGui::PushID(i);

                // Check if this contact is selected
                bool is_selected = std::find(state.create_group_selected_members.begin(),
                                           state.create_group_selected_members.end(),
                                           (int)i) != state.create_group_selected_members.end();

                if (ImGui::Checkbox(state.contacts[i].name.c_str(), &is_selected)) {
                    if (is_selected) {
                        // Add to selection
                        state.create_group_selected_members.push_back((int)i);
                    } else {
                        // Remove from selection
                        auto it = std::find(state.create_group_selected_members.begin(),
                                          state.create_group_selected_members.end(),
                                          (int)i);
                        if (it != state.create_group_selected_members.end()) {
                            state.create_group_selected_members.erase(it);
                        }
                    }
                }

                ImGui::PopID();
            }
        }

        ImGui::EndChild();

        ImGui::Spacing();

        // Status message
        if (!state.create_group_status.empty()) {
            ImVec4 color = state.create_group_status.find("Error") != std::string::npos ||
                          state.create_group_status.find("Failed") != std::string::npos ?
                          (g_app_settings.theme == 0 ? DNATheme::TextWarning() : ClubTheme::TextWarning()) :
                          (g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess());
            ImGui::TextColored(color, "%s", state.create_group_status.c_str());
            ImGui::Spacing();
        }

        // Buttons - horizontal layout like add contact dialog
        bool can_create = strlen(state.create_group_name_input) > 0 &&
                         !state.create_group_selected_members.empty() &&
                         !state.create_group_in_progress;

        float button_width_left = 100.0f;
        float button_width_right = 140.0f;
        float content_width = ImGui::GetContentRegionAvail().x;
        
        // Left button (Cancel)
        if (ThemedButton(ICON_FA_XMARK " Cancel", ImVec2(button_width_left, 40))) {
            state.show_create_group_dialog = false;
            // Clear state
            memset(state.create_group_name_input, 0, sizeof(state.create_group_name_input));
            state.create_group_selected_members.clear();
            state.create_group_status.clear();
            state.create_group_in_progress = false;
        }
        
        // Right button (Create Group) - position to align with right edge
        ImGui::SameLine(0.0f, content_width - button_width_left - button_width_right);
        
        ImGui::BeginDisabled(!can_create);
        if (ThemedButton(ICON_FA_CHECK " Create Group", ImVec2(button_width_right, 40))) {
            state.create_group_in_progress = true;
            state.create_group_status = "Creating group...";

            messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
            if (!ctx) {
                state.create_group_status = "Error: Messenger not initialized";
                state.create_group_in_progress = false;
            } else {
                // Build member list
                std::vector<const char*> member_ptrs;
                for (int contact_idx : state.create_group_selected_members) {
                    if (contact_idx >= 0 && contact_idx < (int)state.contacts.size()) {
                        member_ptrs.push_back(state.contacts[contact_idx].address.c_str());
                    }
                }

                // Create the group (syncs to DHT internally)
                int group_id = 0;
                int ret = messenger_create_group(
                    ctx,
                    state.create_group_name_input,
                    "",  // Empty description for now
                    member_ptrs.data(),
                    member_ptrs.size(),
                    &group_id
                );

                if (ret != 0) {
                    state.create_group_status = "Error: Failed to create group";
                    state.create_group_in_progress = false;
                } else {
                    state.create_group_status = "Group created successfully!";
                    printf("[Create Group] Created group '%s' (ID: %d) with %zu members\n",
                           state.create_group_name_input, group_id,
                           member_ptrs.size());

                    // Reload groups list to show the new group
                    printf("[Create Group] Reloading groups list...\n");
                    state.groups.clear();
                    dht_group_cache_entry_t *groups_array = nullptr;
                    int groups_count = 0;
                    if (dht_groups_list_for_user(state.current_identity.c_str(), &groups_array, &groups_count) == 0 && groups_count > 0) {
                        for (int i = 0; i < groups_count; i++) {
                            Group group;
                            group.local_id = groups_array[i].local_id;
                            group.group_uuid = groups_array[i].group_uuid;
                            group.name = groups_array[i].name;
                            group.creator = groups_array[i].creator;
                            group.member_count = 0;
                            group.created_at = groups_array[i].created_at;
                            group.last_sync = groups_array[i].last_sync;
                            state.groups.push_back(group);
                        }
                        dht_groups_free_cache_entries(groups_array, groups_count);
                        printf("[Create Group] Reloaded %d groups\n", groups_count);
                    }

                    // Close dialog
                    state.show_create_group_dialog = false;

                    // Clear state
                    memset(state.create_group_name_input, 0, sizeof(state.create_group_name_input));
                    state.create_group_selected_members.clear();
                    state.create_group_status.clear();
                    state.create_group_in_progress = false;
                }
            }
        }
        ImGui::EndDisabled();

        CenteredModal::End();
    }
}

} // namespace CreateGroupDialog
