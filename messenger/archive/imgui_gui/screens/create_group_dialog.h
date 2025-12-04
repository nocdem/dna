#ifndef CREATE_GROUP_DIALOG_H
#define CREATE_GROUP_DIALOG_H

#include "../core/app_state.h"

namespace CreateGroupDialog {

/**
 * Render the Create Group modal dialog
 *
 * Shows a dialog for creating a new DHT group:
 * - Group name input (required)
 * - Member selection (checkboxes from contacts list)
 * - Create button (disabled until name and at least 1 member selected)
 * - Cancel button
 *
 * On creation:
 * - Calls messenger_create_group() with selected members
 * - Syncs group to DHT via messenger_sync_group_to_dht()
 * - Closes dialog on success
 */
void render(AppState& state);

} // namespace CreateGroupDialog

#endif // CREATE_GROUP_DIALOG_H
