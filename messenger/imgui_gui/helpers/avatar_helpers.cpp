#include "avatar_helpers.h"
#include <GLFW/glfw3.h>

namespace AvatarHelpers {

void renderCircularAvatar(unsigned int texture_id, float size, ImVec4 border_color, float border_thickness) {
    // Get position for circular rendering
    ImVec2 avatar_pos = ImGui::GetCursorScreenPos();
    ImVec2 avatar_center = ImVec2(avatar_pos.x + size * 0.5f, avatar_pos.y + size * 0.5f);
    float radius = size * 0.5f;
    
    // Create invisible button to advance cursor
    ImGui::InvisibleButton("##circular_avatar", ImVec2(size, size));
    
    // Draw circular avatar using DrawList
    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    
    const int segments = 32;
    draw_list->AddImageRounded(
        (void*)(intptr_t)texture_id,
        avatar_pos,
        ImVec2(avatar_pos.x + size, avatar_pos.y + size),
        ImVec2(0, 0), ImVec2(1, 1),
        IM_COL32(255, 255, 255, 255),
        radius
    );
    
    // Draw circular border
    ImU32 border_color_u32 = IM_COL32(
        (int)(border_color.x * 255), 
        (int)(border_color.y * 255), 
        (int)(border_color.z * 255), 
        (int)(border_color.w * 255)
    );
    draw_list->AddCircle(avatar_center, radius, border_color_u32, segments, border_thickness);
}

} // namespace AvatarHelpers
