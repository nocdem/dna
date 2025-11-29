#include "group_settings_dialog.h"
#include "../imgui.h"
#include "../ui_helpers.h"
#include "../font_awesome.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../../messenger.h"
#include "../../dht/shared/dht_groups.h"
#include "../../p2p/p2p_transport.h"

#include <cstdio>
#include <cstring>

extern AppSettings g_app_settings;

namespace GroupSettingsDialog {

static void renderGroupInfoDialog(AppState& state) {
    if (!state.show_group_info_dialog) return;
    if (state.group_context_menu_index < 0 ||
        state.group_context_menu_index >= (int)state.groups.size()) {
        state.show_group_info_dialog = false;
        return;
    }

    const Group& group = state.groups[state.group_context_menu_index];
    messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
    bool is_owner = ctx && (group.creator == ctx->identity);

    ImGui::OpenPopup("Group Info");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(400, 350), ImGuiCond_Appearing);

    if (ImGui::BeginPopupModal("Group Info", &state.show_group_info_dialog,
                                ImGuiWindowFlags_NoResize)) {
        // Group name header
        ImGui::Text(ICON_FA_USERS " %s", group.name.c_str());
        ImGui::Separator();
        ImGui::Spacing();

        // Group details
        ImGui::Text("UUID: %s", group.group_uuid.c_str());
        ImGui::Text("Created by: %s", group.creator.c_str());
        if (is_owner) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.4f, 0.8f, 0.4f, 1.0f), "(You)");
        }

        // Format created_at timestamp
        char time_str[64];
        time_t created = (time_t)group.created_at;
        struct tm *tm_info = localtime(&created);
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", tm_info);
        ImGui::Text("Created: %s", time_str);

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Members list
        ImGui::Text("Members (%zu):", state.group_members_list.size());
        ImGui::BeginChild("MembersList", ImVec2(0, 150), true);
        for (const auto& member : state.group_members_list) {
            bool is_self = ctx && (member == ctx->identity);
            bool is_creator = (member == group.creator);

            if (is_creator) {
                ImGui::Text(ICON_FA_CROWN " %s", member.c_str());
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.9f, 0.7f, 0.2f, 1.0f), "(Owner)");
            } else if (is_self) {
                ImGui::Text(ICON_FA_USER " %s", member.c_str());
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(0.4f, 0.8f, 0.4f, 1.0f), "(You)");
            } else {
                ImGui::Text(ICON_FA_USER " %s", member.c_str());
            }
        }
        ImGui::EndChild();

        ImGui::Spacing();

        // Close button
        if (ThemedButton("Close", ImVec2(120, 30))) {
            state.show_group_info_dialog = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

static void renderAddMemberDialog(AppState& state) {
    if (!state.show_add_member_dialog) return;
    if (state.group_context_menu_index < 0 ||
        state.group_context_menu_index >= (int)state.groups.size()) {
        state.show_add_member_dialog = false;
        return;
    }

    const Group& group = state.groups[state.group_context_menu_index];

    ImGui::OpenPopup("Add Member");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(400, 400), ImGuiCond_Appearing);

    if (ImGui::BeginPopupModal("Add Member", &state.show_add_member_dialog,
                                ImGuiWindowFlags_NoResize)) {
        ImGui::Text("Add member to: %s", group.name.c_str());
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::Text("Select contacts to add:");
        ImGui::BeginChild("ContactsToAdd", ImVec2(0, 250), true);

        for (size_t i = 0; i < state.contacts.size(); i++) {
            const Contact& contact = state.contacts[i];

            // Check if already a member
            bool already_member = false;
            for (const auto& member : state.group_members_list) {
                if (member == contact.address) {
                    already_member = true;
                    break;
                }
            }

            if (already_member) {
                ImGui::TextDisabled(ICON_FA_USER " %s (already member)",
                                   contact.name.empty() ? contact.address.c_str() : contact.name.c_str());
                continue;
            }

            // Check if selected
            bool is_selected = false;
            for (int sel : state.add_member_selected) {
                if (sel == (int)i) {
                    is_selected = true;
                    break;
                }
            }

            ImGui::PushID((int)i);
            if (ImGui::Checkbox("##sel", &is_selected)) {
                if (is_selected) {
                    state.add_member_selected.push_back((int)i);
                } else {
                    auto it = std::find(state.add_member_selected.begin(),
                                       state.add_member_selected.end(), (int)i);
                    if (it != state.add_member_selected.end()) {
                        state.add_member_selected.erase(it);
                    }
                }
            }
            ImGui::SameLine();
            ImGui::Text(ICON_FA_USER " %s",
                       contact.name.empty() ? contact.address.c_str() : contact.name.c_str());
            ImGui::PopID();
        }
        ImGui::EndChild();

        if (!state.group_action_status.empty()) {
            ImVec4 color = state.group_action_status.find("Error") != std::string::npos ?
                          ImVec4(1.0f, 0.3f, 0.3f, 1.0f) : ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
            ImGui::TextColored(color, "%s", state.group_action_status.c_str());
        }

        ImGui::Spacing();

        // Buttons
        bool can_add = !state.add_member_selected.empty();
        ImGui::BeginDisabled(!can_add);
        if (ThemedButton(ICON_FA_USER_PLUS " Add Selected", ImVec2(150, 30))) {
            messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
            if (ctx) {
                int success_count = 0;
                for (int idx : state.add_member_selected) {
                    if (idx >= 0 && idx < (int)state.contacts.size()) {
                        const char *identity = state.contacts[idx].address.c_str();
                        if (messenger_add_group_member(ctx, group.local_id, identity) == 0) {
                            success_count++;
                            printf("[Group] Added member: %s\n", identity);
                        }
                    }
                }
                state.group_action_status = "Added " + std::to_string(success_count) + " member(s)";
                state.add_member_selected.clear();

                // Reload members list
                dht_context_t *dht_ctx = ctx->p2p_transport ?
                    p2p_transport_get_dht_context(ctx->p2p_transport) : nullptr;
                if (dht_ctx) {
                    state.group_members_list.clear();
                    dht_group_metadata_t *meta = nullptr;
                    if (dht_groups_get(dht_ctx, group.group_uuid.c_str(), &meta) == 0 && meta) {
                        for (uint32_t m = 0; m < meta->member_count; m++) {
                            state.group_members_list.push_back(meta->members[m]);
                        }
                        dht_groups_free_metadata(meta);
                    }
                }
            }
        }
        ImGui::EndDisabled();

        ImGui::SameLine();
        if (ThemedButton("Cancel", ImVec2(100, 30))) {
            state.show_add_member_dialog = false;
            state.group_action_status.clear();
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

static void renderLeaveGroupConfirm(AppState& state) {
    if (!state.show_leave_group_confirm) return;
    if (state.group_context_menu_index < 0 ||
        state.group_context_menu_index >= (int)state.groups.size()) {
        state.show_leave_group_confirm = false;
        return;
    }

    const Group& group = state.groups[state.group_context_menu_index];

    ImGui::OpenPopup("Leave Group?");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Leave Group?", &state.show_leave_group_confirm,
                                ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Are you sure you want to leave");
        ImGui::Text(ICON_FA_USERS " %s?", group.name.c_str());
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.7f, 0.3f, 1.0f),
                          "You will no longer receive messages from this group.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ThemedButton(ICON_FA_RIGHT_FROM_BRACKET " Leave", ImVec2(120, 30))) {
            messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
            if (ctx) {
                if (messenger_leave_group(ctx, group.local_id) == 0) {
                    printf("[Group] Left group: %s\n", group.name.c_str());
                    // Reload groups list
                    state.groups.clear();
                    dht_group_cache_entry_t *groups_array = nullptr;
                    int groups_count = 0;
                    if (dht_groups_list_for_user(state.current_identity.c_str(),
                                                  &groups_array, &groups_count) == 0 && groups_count > 0) {
                        for (int i = 0; i < groups_count; i++) {
                            Group g;
                            g.local_id = groups_array[i].local_id;
                            g.group_uuid = groups_array[i].group_uuid;
                            g.name = groups_array[i].name;
                            g.creator = groups_array[i].creator;
                            g.member_count = 0;
                            g.created_at = groups_array[i].created_at;
                            g.last_sync = groups_array[i].last_sync;
                            state.groups.push_back(g);
                        }
                        dht_groups_free_cache_entries(groups_array, groups_count);
                    }
                } else {
                    printf("[Group] Failed to leave group\n");
                }
            }
            state.show_leave_group_confirm = false;
            state.group_context_menu_index = -1;
            ImGui::CloseCurrentPopup();
        }

        ImGui::SameLine();
        if (ThemedButton("Cancel", ImVec2(100, 30))) {
            state.show_leave_group_confirm = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

static void renderDeleteGroupConfirm(AppState& state) {
    if (!state.show_delete_group_confirm) return;
    if (state.group_context_menu_index < 0 ||
        state.group_context_menu_index >= (int)state.groups.size()) {
        state.show_delete_group_confirm = false;
        return;
    }

    const Group& group = state.groups[state.group_context_menu_index];

    ImGui::OpenPopup("Delete Group?");
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));

    if (ImGui::BeginPopupModal("Delete Group?", &state.show_delete_group_confirm,
                                ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), ICON_FA_TRIANGLE_EXCLAMATION " Warning");
        ImGui::Spacing();
        ImGui::Text("Are you sure you want to DELETE");
        ImGui::Text(ICON_FA_USERS " %s?", group.name.c_str());
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.3f, 1.0f),
                          "This action cannot be undone!");
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.3f, 1.0f),
                          "All members will lose access to the group.");
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1.0f, 0.3f, 0.3f, 1.0f));
        if (ImGui::Button(ICON_FA_TRASH " Delete", ImVec2(120, 30))) {
            messenger_context_t *ctx = (messenger_context_t*)state.messenger_ctx;
            if (ctx) {
                if (messenger_delete_group(ctx, group.local_id) == 0) {
                    printf("[Group] Deleted group: %s\n", group.name.c_str());
                    // Clear selection if viewing this group
                    if (state.selected_group == state.group_context_menu_index) {
                        state.selected_group = -1;
                        state.is_viewing_group = false;
                    }
                    // Reload groups list
                    state.groups.clear();
                    dht_group_cache_entry_t *groups_array = nullptr;
                    int groups_count = 0;
                    if (dht_groups_list_for_user(state.current_identity.c_str(),
                                                  &groups_array, &groups_count) == 0 && groups_count > 0) {
                        for (int i = 0; i < groups_count; i++) {
                            Group g;
                            g.local_id = groups_array[i].local_id;
                            g.group_uuid = groups_array[i].group_uuid;
                            g.name = groups_array[i].name;
                            g.creator = groups_array[i].creator;
                            g.member_count = 0;
                            g.created_at = groups_array[i].created_at;
                            g.last_sync = groups_array[i].last_sync;
                            state.groups.push_back(g);
                        }
                        dht_groups_free_cache_entries(groups_array, groups_count);
                    }
                } else {
                    printf("[Group] Failed to delete group\n");
                }
            }
            state.show_delete_group_confirm = false;
            state.group_context_menu_index = -1;
            ImGui::CloseCurrentPopup();
        }
        ImGui::PopStyleColor(2);

        ImGui::SameLine();
        if (ThemedButton("Cancel", ImVec2(100, 30))) {
            state.show_delete_group_confirm = false;
            ImGui::CloseCurrentPopup();
        }

        ImGui::EndPopup();
    }
}

void render(AppState& state) {
    renderGroupInfoDialog(state);
    renderAddMemberDialog(state);
    renderLeaveGroupConfirm(state);
    renderDeleteGroupConfirm(state);
}

} // namespace GroupSettingsDialog
