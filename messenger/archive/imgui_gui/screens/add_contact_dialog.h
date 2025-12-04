#ifndef ADD_CONTACT_DIALOG_H
#define ADD_CONTACT_DIALOG_H

#include "../core/app_state.h"
#include <functional>

namespace AddContactDialog {
    // Render the add contact dialog
    // reload_contacts_callback: Called after successfully adding a contact
    void render(AppState& state, std::function<void()> reload_contacts_callback);
}

#endif // ADD_CONTACT_DIALOG_H
