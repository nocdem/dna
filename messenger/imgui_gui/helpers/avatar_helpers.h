#ifndef AVATAR_HELPERS_H
#define AVATAR_HELPERS_H

#include "../imgui.h"
#include <string>

namespace AvatarHelpers {
    /**
     * @brief Render a circular avatar with border
     * @param texture_id OpenGL texture ID
     * @param size Avatar size (width and height)
     * @param border_color Border color as ImVec4
     * @param border_thickness Border thickness in pixels
     */
    void renderCircularAvatar(unsigned int texture_id, float size, ImVec4 border_color, float border_thickness = 0.5f);
}

#endif // AVATAR_HELPERS_H
