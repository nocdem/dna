#ifndef GROUP_SETTINGS_DIALOG_H
#define GROUP_SETTINGS_DIALOG_H

#include "../core/app_state.h"

namespace GroupSettingsDialog {

/**
 * Render all group management dialogs
 * - Group Info dialog
 * - Add Member dialog
 * - Leave Group confirmation
 * - Delete Group confirmation
 */
void render(AppState& state);

} // namespace GroupSettingsDialog

#endif // GROUP_SETTINGS_DIALOG_H
