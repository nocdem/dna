#ifndef IDENTITY_HELPERS_H
#define IDENTITY_HELPERS_H

#include "imgui.h"

// Input filter callback for identity name (alphanumeric + underscore only)
inline int IdentityNameInputFilter(ImGuiInputTextCallbackData* data) {
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

#endif // IDENTITY_HELPERS_H
