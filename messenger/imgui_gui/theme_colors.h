#ifndef THEME_COLORS_H
#define THEME_COLORS_H

#include "imgui.h"

// DNA Theme (cpunk.io)
namespace DNATheme {
    inline ImVec4 Background() { return ImVec4(0.098f, 0.114f, 0.129f, 1.0f); }  // #191D21
    inline ImVec4 Text() { return ImVec4(0.0f, 1.0f, 0.8f, 1.0f); }              // #00FFCC
    inline ImVec4 TextDisabled() { return ImVec4(0.8f, 0.8f, 0.8f, 1.0f); }     // #CCCCCC
    inline ImVec4 TextHint() { return ImVec4(0.7f, 0.7f, 0.7f, 1.0f); }         // #B3B3B3 - Subtle hint text
    inline ImVec4 TextWarning() { return ImVec4(1.0f, 0.5f, 0.5f, 1.0f); }      // #FF8080 - Softer red warning
    inline ImVec4 TextSuccess() { return ImVec4(0.5f, 1.0f, 0.5f, 1.0f); }      // #80FF80 - Softer green success
    inline ImVec4 TextInfo() { return ImVec4(1.0f, 0.8f, 0.4f, 1.0f); }         // #FFCC66 - Orange/amber info
    inline ImVec4 OfflineColor() { return ImVec4(0.867f, 0.867f, 0.867f, 1.0f); }// #DDDDDD (lighter for visibility)
    inline ImVec4 ButtonHover() { return ImVec4(0.0f, 0.85f, 0.68f, 1.0f); }    // Slightly darker cyan
    inline ImVec4 ButtonActive() { return ImVec4(0.0f, 0.75f, 0.60f, 1.0f); }   // Even darker cyan
    inline ImVec4 SelectedText() { return ImVec4(0.098f, 0.114f, 0.129f, 1.0f); }// Same as background
    inline ImVec4 Separator() { return ImVec4(0.0f, 1.0f, 0.8f, 0.3f); }        // #00FFCC with alpha
    inline ImVec4 Border() { return ImVec4(0.0f, 1.0f, 0.8f, 0.3f); }           // #00FFCC with alpha
    inline ImVec4 InputBackground() { return ImVec4(0.12f, 0.14f, 0.16f, 1.0f); }// Slightly lighter than bg
}

// Club Theme (cpunk.club)
namespace ClubTheme {
    inline ImVec4 Background() { return ImVec4(0.125f, 0.114f, 0.110f, 1.0f); } // #201D1C
    inline ImVec4 Text() { return ImVec4(0.976f, 0.471f, 0.204f, 1.0f); }       // #F97834
    inline ImVec4 TextDisabled() { return ImVec4(0.8f, 0.8f, 0.8f, 1.0f); }    // #CCCCCC
    inline ImVec4 TextHint() { return ImVec4(0.7f, 0.7f, 0.7f, 1.0f); }        // #B3B3B3 - Subtle hint text
    inline ImVec4 TextWarning() { return ImVec4(1.0f, 0.5f, 0.5f, 1.0f); }     // #FF8080 - Softer red warning
    inline ImVec4 TextSuccess() { return ImVec4(0.5f, 1.0f, 0.5f, 1.0f); }     // #80FF80 - Softer green success
    inline ImVec4 TextInfo() { return ImVec4(1.0f, 0.8f, 0.4f, 1.0f); }        // #FFCC66 - Orange/amber info
    inline ImVec4 OfflineColor() { return ImVec4(0.867f, 0.867f, 0.867f, 1.0f); }// #DDDDDD (lighter for visibility)
    inline ImVec4 ButtonHover() { return ImVec4(0.876f, 0.400f, 0.184f, 1.0f); }// Slightly darker orange
    inline ImVec4 ButtonActive() { return ImVec4(0.776f, 0.350f, 0.164f, 1.0f); }// Even darker orange
    inline ImVec4 SelectedText() { return ImVec4(0.125f, 0.114f, 0.110f, 1.0f); }// Same as background
    inline ImVec4 Separator() { return ImVec4(0.976f, 0.471f, 0.204f, 0.3f); }  // #F97834 with alpha
    inline ImVec4 Border() { return ImVec4(0.976f, 0.471f, 0.204f, 0.3f); }     // #F97834 with alpha
    inline ImVec4 InputBackground() { return ImVec4(0.15f, 0.14f, 0.13f, 1.0f); }// Slightly lighter than bg
}

#endif // THEME_COLORS_H
