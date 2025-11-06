#ifndef THEME_COLORS_H
#define THEME_COLORS_H

#include "imgui.h"

// DNA Theme (cpunk.io)
namespace DNATheme {
    inline ImVec4 Background() { return ImVec4(0.098f, 0.114f, 0.129f, 1.0f); }  // #191D21
    inline ImVec4 Text() { return ImVec4(0.0f, 1.0f, 0.8f, 1.0f); }              // #00FFCC
    inline ImVec4 TextDisabled() { return ImVec4(0.8f, 0.8f, 0.8f, 1.0f); }     // #CCCCCC
    inline ImVec4 OfflineColor() { return ImVec4(0.867f, 0.867f, 0.867f, 1.0f); }// #DDDDDD (lighter for visibility)
    inline ImVec4 ButtonHover() { return ImVec4(0.078f, 0.094f, 0.109f, 1.0f); } // Slightly darker
    inline ImVec4 ButtonActive() { return ImVec4(0.068f, 0.084f, 0.099f, 1.0f); }// Even darker
    inline ImVec4 SelectedText() { return ImVec4(0.098f, 0.114f, 0.129f, 1.0f); }// Same as background
    inline ImVec4 Separator() { return ImVec4(0.0f, 1.0f, 0.8f, 0.3f); }        // #00FFCC with alpha
    inline ImVec4 Border() { return ImVec4(0.0f, 1.0f, 0.8f, 0.3f); }           // #00FFCC with alpha
}

// Club Theme (cpunk.club)
namespace ClubTheme {
    inline ImVec4 Background() { return ImVec4(0.125f, 0.114f, 0.110f, 1.0f); } // #201D1C
    inline ImVec4 Text() { return ImVec4(0.976f, 0.471f, 0.204f, 1.0f); }       // #F97834
    inline ImVec4 TextDisabled() { return ImVec4(0.8f, 0.8f, 0.8f, 1.0f); }    // #CCCCCC
    inline ImVec4 OfflineColor() { return ImVec4(0.867f, 0.867f, 0.867f, 1.0f); }// #DDDDDD (lighter for visibility)
    inline ImVec4 ButtonHover() { return ImVec4(0.105f, 0.094f, 0.090f, 1.0f); }// Slightly darker
    inline ImVec4 ButtonActive() { return ImVec4(0.095f, 0.084f, 0.080f, 1.0f); }// Even darker
    inline ImVec4 SelectedText() { return ImVec4(0.125f, 0.114f, 0.110f, 1.0f); }// Same as background
    inline ImVec4 Separator() { return ImVec4(0.976f, 0.471f, 0.204f, 0.3f); }  // #F97834 with alpha
    inline ImVec4 Border() { return ImVec4(0.976f, 0.471f, 0.204f, 0.3f); }     // #F97834 with alpha
}

#endif // THEME_COLORS_H
