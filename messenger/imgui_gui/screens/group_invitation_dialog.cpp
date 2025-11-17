#include "group_invitation_dialog.h"
#include "../imgui.h"
#include "../modal_helper.h"
#include "../ui_helpers.h"
#include "../theme_colors.h"
#include "../settings_manager.h"
#include "../font_awesome.h"
#include "../../messenger.h"
#include "../../database/group_invitations.h"
#include "../../dht/shared/dht_groups.h"
#include "../helpers/data_loader.h"

#include <cstring>
#include <cstdio>
#include <ctime>

// External settings variable
extern AppSettings g_app_settings;

namespace GroupInvitationDialog {

// Helper to format timestamp
static std::string formatTimestamp(uint64_t timestamp) {
    time_t t = (time_t)timestamp;
    struct tm *tm_info = localtime(&t);
    char buffer[64];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M", tm_info);
    return std::string(buffer);
}

// Helper to reload groups and invitations after accepting
static void reloadGroupsAndInvitations(AppState& state) {
    // Clear existing data
    state.groups.clear();
    state.pending_invitations.clear();

    // Load groups for this identity
    dht_group_cache_entry_t *groups_array = nullptr;
    int groups_count = 0;
    if (dht_groups_list_for_user(state.current_identity.c_str(), &groups_array, &groups_count) == 0 && groups_count > 0) {
        for (int i = 0; i < groups_count; i++) {
            Group group;
            group.local_id = groups_array[i].local_id;
            group.group_uuid = groups_array[i].group_uuid;
            group.name = groups_array[i].name;
            group.creator = groups_array[i].creator;
            group.member_count = 0;  // member_count not stored in cache, will be loaded from DHT metadata
            group.created_at = groups_array[i].created_at;
            group.last_sync = groups_array[i].last_sync;
            state.groups.push_back(group);
        }
        free(groups_array);
    }

    // Load pending invitations
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
        free(invitations_array);
    }
}

void render(AppState& state) {
    if (!CenteredModal::Begin("Group Invitation", &state.show_group_invitation_dialog, ImGuiWindowFlags_NoResize, true, false, 500)) {
        // Reset state when dialog closes
        if (!state.show_group_invitation_dialog) {
            state.selected_invitation_index = -1;
            state.invitation_action_status.clear();
            state.invitation_action_in_progress = false;
        }
        return;
    }

    ImGuiIO& io = ImGui::GetIO();
    bool is_mobile = IsMobileLayout();

    // Validate selected invitation index
    if (state.selected_invitation_index < 0 ||
        state.selected_invitation_index >= (int)state.pending_invitations.size()) {
        ImGui::Text("Error: Invalid invitation selected");
        ImGui::Spacing();
        if (ImGui::Button("Close")) {
            state.show_group_invitation_dialog = false;
        }
        CenteredModal::End();
        return;
    }

    const GroupInvitation& invitation = state.pending_invitations[state.selected_invitation_index];

    // Header with icon
    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(),
                       "%s  Group Invitation", ICON_FA_ENVELOPE);
    ImGui::Separator();
    ImGui::Spacing();

    // Display invitation details
    ImGui::Text("You have been invited to join:");
    ImGui::Spacing();

    // Group name (highlighted)
    ImGui::PushFont(io.Fonts->Fonts[0]); // Use default font (or larger if available)
    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(),
                       "%s", invitation.group_name.c_str());
    ImGui::PopFont();
    ImGui::Spacing();

    // Invitation details
    ImGui::Text("Invited by:");
    ImGui::SameLine();
    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(),
                       "%s", invitation.inviter.c_str());

    ImGui::Text("Members:");
    ImGui::SameLine();
    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(),
                       "%d", invitation.member_count);

    ImGui::Text("Invited:");
    ImGui::SameLine();
    ImGui::TextColored(g_app_settings.theme == 0 ? DNATheme::Text() : ClubTheme::Text(),
                       "%s", formatTimestamp(invitation.invited_at).c_str());

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // Status message
    if (!state.invitation_action_status.empty()) {
        bool is_error = (state.invitation_action_status.find("Error") != std::string::npos ||
                        state.invitation_action_status.find("Failed") != std::string::npos);
        ImVec4 status_color = is_error ?
            ImVec4(1.0f, 0.3f, 0.3f, 1.0f) :
            (g_app_settings.theme == 0 ? DNATheme::TextSuccess() : ClubTheme::TextSuccess());

        ImGui::TextColored(status_color, "%s", state.invitation_action_status.c_str());
        ImGui::Spacing();
    }

    // Action buttons
    ImGui::BeginDisabled(state.invitation_action_in_progress);

    // Accept button (green)
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.7f, 0.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.8f, 0.3f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.1f, 0.6f, 0.1f, 1.0f));

    float button_width = (ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ItemSpacing.x) / 2.0f;
    if (ImGui::Button(ICON_FA_CHECK "  Accept", ImVec2(button_width, 40))) {
        state.invitation_action_in_progress = true;
        state.invitation_action_status = "Accepting invitation...";

        // Call backend to accept invitation
        messenger_context_t *ctx = (messenger_context_t *)state.messenger_ctx;
        if (ctx) {
            int result = messenger_accept_group_invitation(ctx, invitation.group_uuid.c_str());
            if (result == 0) {
                state.invitation_action_status = "✓ Invitation accepted! Group added.";
                // Reload groups and invitations
                reloadGroupsAndInvitations(state);
                // Close dialog after short delay (let user see success message)
                // For now, just set flag to close on next frame
                state.invitation_action_in_progress = false;
            } else {
                state.invitation_action_status = "Error: Failed to accept invitation";
                state.invitation_action_in_progress = false;
            }
        } else {
            state.invitation_action_status = "Error: Messenger context not initialized";
            state.invitation_action_in_progress = false;
        }
    }
    ImGui::PopStyleColor(3);

    ImGui::SameLine();

    // Reject button (red)
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.7f, 0.2f, 0.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.8f, 0.3f, 0.3f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0.6f, 0.1f, 0.1f, 1.0f));

    if (ImGui::Button(ICON_FA_XMARK "  Reject", ImVec2(button_width, 40))) {
        state.invitation_action_in_progress = true;
        state.invitation_action_status = "Rejecting invitation...";

        // Call backend to reject invitation
        messenger_context_t *ctx = (messenger_context_t *)state.messenger_ctx;
        if (ctx) {
            int result = messenger_reject_group_invitation(ctx, invitation.group_uuid.c_str());
            if (result == 0) {
                state.invitation_action_status = "✓ Invitation rejected";
                // Reload invitations (remove from list)
                reloadGroupsAndInvitations(state);
                // Close dialog
                state.invitation_action_in_progress = false;
            } else {
                state.invitation_action_status = "Error: Failed to reject invitation";
                state.invitation_action_in_progress = false;
            }
        } else {
            state.invitation_action_status = "Error: Messenger context not initialized";
            state.invitation_action_in_progress = false;
        }
    }
    ImGui::PopStyleColor(3);

    ImGui::EndDisabled();

    // Close button at bottom
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::Button("Close", ImVec2(-1, 0))) {
        state.show_group_invitation_dialog = false;
        state.selected_invitation_index = -1;
        state.invitation_action_status.clear();
        state.invitation_action_in_progress = false;
    }

    CenteredModal::End();
}

} // namespace GroupInvitationDialog
