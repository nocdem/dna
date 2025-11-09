// DNA Messenger - ImGui GUI
// Modern, lightweight, cross-platform messenger interface
// UI SKETCH MODE - Backend integration disabled for UI development

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "imgui_freetype.h"
#include "modal_helper.h"
#include "font_awesome.h"
#include "theme_colors.h"
#include "settings_manager.h"
#include "ui_helpers.h"
#include "app.h"
#include <GLFW/glfw3.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>

// Backend includes
extern "C" {
    #include "../dht/dht_singleton.h"
}
#include <algorithm>
#include <cstdlib>
#include <cmath>

#ifndef _WIN32
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <windows.h>
#include <direct.h>
#endif

// Comment out backend includes for UI sketch mode
/*
extern "C" {
#include "../dna_api.h"
#include "../messenger_p2p.h"
#include "../messenger.h"
#include "../wallet.h"
#include "../messenger/keyserver_register.h"
#include "../bip39.h"
}
*/

// Global settings
AppSettings g_app_settings;

// Apply theme colors to ImGui
void ApplyTheme(int theme) {
    ImGuiStyle& style = ImGui::GetStyle();

    if (theme == 0) { // DNA Theme
        style.Colors[ImGuiCol_Text] = DNATheme::Text();
        style.Colors[ImGuiCol_TextDisabled] = DNATheme::TextDisabled();
        style.Colors[ImGuiCol_WindowBg] = DNATheme::Background();
        style.Colors[ImGuiCol_ChildBg] = DNATheme::Background();
        style.Colors[ImGuiCol_PopupBg] = DNATheme::Background();
        style.Colors[ImGuiCol_Border] = DNATheme::Border();
        style.Colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
        style.Colors[ImGuiCol_FrameBg] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_FrameBgHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_FrameBgActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_TitleBg] = DNATheme::Background();
        style.Colors[ImGuiCol_TitleBgActive] = DNATheme::Background();
        style.Colors[ImGuiCol_TitleBgCollapsed] = DNATheme::Background();
        style.Colors[ImGuiCol_MenuBarBg] = DNATheme::Background();
        style.Colors[ImGuiCol_ScrollbarBg] = DNATheme::Background();
        style.Colors[ImGuiCol_ScrollbarGrab] = DNATheme::Text();
        style.Colors[ImGuiCol_ScrollbarGrabHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_ScrollbarGrabActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_CheckMark] = DNATheme::Background(); // Dark background for inner circle
        style.Colors[ImGuiCol_SliderGrab] = DNATheme::Text();
        style.Colors[ImGuiCol_SliderGrabActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Button] = DNATheme::Text();
        style.Colors[ImGuiCol_ButtonHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_ButtonActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Header] = ImVec4(0.0f, 1.0f, 0.8f, 0.2f); // 20% opacity
        style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.0f, 1.0f, 0.8f, 0.4f); // 40% opacity - visible but not too bright
        style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.0f, 1.0f, 0.8f, 0.5f); // 50% opacity
        style.Colors[ImGuiCol_Separator] = DNATheme::Separator();
        style.Colors[ImGuiCol_SeparatorHovered] = DNATheme::Text();
        style.Colors[ImGuiCol_SeparatorActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_ResizeGrip] = DNATheme::Text();
        style.Colors[ImGuiCol_ResizeGripHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_ResizeGripActive] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_Tab] = DNATheme::Background();
        style.Colors[ImGuiCol_TabHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TabSelected] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_TabSelectedOverline] = DNATheme::Text();
        style.Colors[ImGuiCol_TabDimmed] = DNATheme::Background();
        style.Colors[ImGuiCol_TabDimmedSelected] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TabDimmedSelectedOverline] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_PlotLines] = DNATheme::Text();
        style.Colors[ImGuiCol_PlotLinesHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_PlotHistogram] = DNATheme::Text();
        style.Colors[ImGuiCol_PlotHistogramHovered] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TableHeaderBg] = DNATheme::Background();
        style.Colors[ImGuiCol_TableBorderStrong] = DNATheme::Border();
        style.Colors[ImGuiCol_TableBorderLight] = DNATheme::Border();
        style.Colors[ImGuiCol_TableRowBg] = DNATheme::Background();
        style.Colors[ImGuiCol_TableRowBgAlt] = DNATheme::ButtonHover();
        style.Colors[ImGuiCol_TextSelectedBg] = DNATheme::ButtonActive();
        style.Colors[ImGuiCol_DragDropTarget] = DNATheme::Text();
        style.Colors[ImGuiCol_NavHighlight] = DNATheme::Text();
        style.Colors[ImGuiCol_NavWindowingHighlight] = DNATheme::Text();
        style.Colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.2f);
        style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.35f);
    } else { // Club Theme
        style.Colors[ImGuiCol_Text] = ClubTheme::Text();
        style.Colors[ImGuiCol_TextDisabled] = ClubTheme::TextDisabled();
        style.Colors[ImGuiCol_WindowBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_ChildBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_PopupBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_Border] = ClubTheme::Border();
        style.Colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
        style.Colors[ImGuiCol_FrameBg] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_FrameBgHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_FrameBgActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_TitleBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_TitleBgActive] = ClubTheme::Background();
        style.Colors[ImGuiCol_TitleBgCollapsed] = ClubTheme::Background();
        style.Colors[ImGuiCol_MenuBarBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_ScrollbarBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_ScrollbarGrab] = ClubTheme::Text();
        style.Colors[ImGuiCol_ScrollbarGrabHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_ScrollbarGrabActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_CheckMark] = ClubTheme::Background(); // Dark background for inner circle
        style.Colors[ImGuiCol_SliderGrab] = ClubTheme::Text();
        style.Colors[ImGuiCol_SliderGrabActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Button] = ClubTheme::Text();
        style.Colors[ImGuiCol_ButtonHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_ButtonActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Header] = ImVec4(0.976f, 0.471f, 0.204f, 0.2f); // 20% opacity
        style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.976f, 0.471f, 0.204f, 0.4f); // 40% opacity - visible but not too bright
        style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.976f, 0.471f, 0.204f, 0.5f); // 50% opacity
        style.Colors[ImGuiCol_Separator] = ClubTheme::Separator();
        style.Colors[ImGuiCol_SeparatorHovered] = ClubTheme::Text();
        style.Colors[ImGuiCol_SeparatorActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_ResizeGrip] = ClubTheme::Text();
        style.Colors[ImGuiCol_ResizeGripHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_ResizeGripActive] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_Tab] = ClubTheme::Background();
        style.Colors[ImGuiCol_TabHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TabSelected] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_TabSelectedOverline] = ClubTheme::Text();
        style.Colors[ImGuiCol_TabDimmed] = ClubTheme::Background();
        style.Colors[ImGuiCol_TabDimmedSelected] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TabDimmedSelectedOverline] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_PlotLines] = ClubTheme::Text();
        style.Colors[ImGuiCol_PlotLinesHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_PlotHistogram] = ClubTheme::Text();
        style.Colors[ImGuiCol_PlotHistogramHovered] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TableHeaderBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_TableBorderStrong] = ClubTheme::Border();
        style.Colors[ImGuiCol_TableBorderLight] = ClubTheme::Border();
        style.Colors[ImGuiCol_TableRowBg] = ClubTheme::Background();
        style.Colors[ImGuiCol_TableRowBgAlt] = ClubTheme::ButtonHover();
        style.Colors[ImGuiCol_TextSelectedBg] = ClubTheme::ButtonActive();
        style.Colors[ImGuiCol_DragDropTarget] = ClubTheme::Text();
        style.Colors[ImGuiCol_NavHighlight] = ClubTheme::Text();
        style.Colors[ImGuiCol_NavWindowingHighlight] = ClubTheme::Text();
        style.Colors[ImGuiCol_NavWindowingDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.2f);
        style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(0.2f, 0.2f, 0.2f, 0.35f);
    }
}



static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
}

int main(int argc, char** argv) {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    // Load settings from file
    SettingsManager::Load(g_app_settings);
    printf("[SKETCH MODE] Settings loaded: theme=%d, window=%dx%d\n",
           g_app_settings.theme, g_app_settings.window_width, g_app_settings.window_height);

    GLFWwindow* window = glfwCreateWindow(g_app_settings.window_width, g_app_settings.window_height, "DNA Messenger", nullptr, nullptr);
    if (window == nullptr)
        return 1;

    // Set minimum window size for desktop
    glfwSetWindowSizeLimits(window, 1000, 600, GLFW_DONT_CARE, GLFW_DONT_CARE);

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = "dna_messenger.ini"; // Enable INI saving

        // Load embedded fonts
    #include "fonts/NotoSans-Regular.h"
    #include "fonts/fa-solid-900.h"

    ImFontConfig config;
    config.MergeMode = false;
    config.FontDataOwnedByAtlas = false; // Don't let ImGui free our static embedded data

    // Base font size (will be scaled by ui_scale via FontScaleMain)
    float base_size = 18.0f;
    io.Fonts->AddFontFromMemoryTTF((void*)NotoSans_Regular_ttf, sizeof(NotoSans_Regular_ttf), base_size, &config);

    // Merge Font Awesome icons
    config.MergeMode = true;
    config.GlyphMinAdvanceX = base_size;
    config.GlyphOffset = ImVec2(0, 2);
    config.FontDataOwnedByAtlas = false;
    static const ImWchar icon_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
    io.Fonts->AddFontFromMemoryTTF((void*)fa_solid_900_ttf, sizeof(fa_solid_900_ttf), base_size * 0.9f, &config, icon_ranges);

    ImGui::StyleColorsDark();

    // DNA Messenger styling
    ImGuiStyle& style = ImGui::GetStyle();

    // Rounding
    style.FrameRounding = 4.0f;
    style.WindowRounding = 8.0f;
    style.ChildRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.TabRounding = 4.0f;
    style.ScrollbarRounding = 4.0f;

    // Selective borders: keep child borders (sidebar), remove others
    style.WindowBorderSize = 0.0f;
    style.FrameBorderSize = 0.0f;
    style.PopupBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;  // Keep this for sidebar

    // Apply initial theme (DNA theme by default)
    ApplyTheme(g_app_settings.theme);
    
    // Apply native ImGui scaling (fonts + UI elements)
    style.ScaleAllSizes(g_app_settings.ui_scale);
    style.FontScaleMain = g_app_settings.ui_scale;

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    DNAMessengerApp app;

    // Initialize global DHT singleton with loading screen
    // Show spinner while bootstrapping DHT
    bool dht_initialized = false;
    bool dht_init_attempted = false;
    float dht_init_start_time = 0.0f;
    
    printf("[MAIN] DHT initialization will happen with loading screen...\n");

    // Track fullscreen state
    static bool is_fullscreen = false;
    static int windowed_xpos, windowed_ypos, windowed_width, windowed_height;
    static bool f11_was_pressed = false;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        
        // Initialize DHT on first frame after window is ready
        if (!dht_init_attempted) {
            dht_init_attempted = true;
            dht_init_start_time = (float)glfwGetTime();
            printf("[MAIN] Starting DHT bootstrap...\n");
            
            if (dht_singleton_init() != 0) {
                fprintf(stderr, "[MAIN] ERROR: Failed to initialize DHT network\n");
                fprintf(stderr, "[MAIN] Continuing without DHT (offline mode)...\n");
            } else {
                printf("[MAIN] ✓ DHT ready!\n");
            }
            dht_initialized = true;
        }
        
        // Show loading spinner until DHT is ready (at least 0.5 seconds for smooth UX)
        float elapsed = (float)glfwGetTime() - dht_init_start_time;
        if (!dht_initialized || elapsed < 0.5f) {
            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();
            
            // Full-screen loading spinner
            ImGui::SetNextWindowPos(ImVec2(0, 0));
            ImGui::SetNextWindowSize(io.DisplaySize);
            ImGui::Begin("Loading", nullptr, 
                ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | 
                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse |
                ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);
            
            // Center spinner
            float spinner_radius = 40.0f;
            ImVec2 center = ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f);
            ImGui::SetCursorScreenPos(ImVec2(center.x - spinner_radius, center.y - spinner_radius));
            
            ThemedSpinner("dht_loading", spinner_radius, 6.0f);
            
            // Loading text below spinner
            const char* loading_text = "Initializing DHT Network...";
            ImVec2 text_size = ImGui::CalcTextSize(loading_text);
            ImGui::SetCursorScreenPos(ImVec2(center.x - text_size.x * 0.5f, center.y + spinner_radius + 30.0f));
            ImGui::Text("%s", loading_text);
            
            ImGui::End();
            
            ImGui::Render();
            int display_w, display_h;
            glfwGetFramebufferSize(window, &display_w, &display_h);
            glViewport(0, 0, display_w, display_h);
            glClearColor(0x15/255.0f, 0x17/255.0f, 0x19/255.0f, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            glfwSwapBuffers(window);
            continue;
        }

        // F11 to toggle fullscreen
        if (glfwGetKey(window, GLFW_KEY_F11) == GLFW_PRESS) {
            if (!f11_was_pressed) {
                f11_was_pressed = true;
                
                if (!is_fullscreen) {
                    // Save windowed position and size
                    glfwGetWindowPos(window, &windowed_xpos, &windowed_ypos);
                    glfwGetWindowSize(window, &windowed_width, &windowed_height);
                    
                    // Switch to fullscreen
                    GLFWmonitor* monitor = glfwGetPrimaryMonitor();
                    const GLFWvidmode* mode = glfwGetVideoMode(monitor);
                    glfwSetWindowMonitor(window, monitor, 0, 0, mode->width, mode->height, mode->refreshRate);
                    is_fullscreen = true;
                } else {
                    // Restore windowed mode
                    glfwSetWindowMonitor(window, nullptr, windowed_xpos, windowed_ypos, windowed_width, windowed_height, 0);
                    is_fullscreen = false;
                }
            }
        } else {
            f11_was_pressed = false;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        app.render();

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0x15/255.0f, 0x17/255.0f, 0x19/255.0f, 1.0f); // #151719
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    // Save window size before exit
    int width, height;
    glfwGetWindowSize(window, &width, &height);
    g_app_settings.window_width = width;
    g_app_settings.window_height = height;
    SettingsManager::Save(g_app_settings);

    // Cleanup global DHT singleton on app shutdown
    printf("[MAIN] Cleaning up DHT singleton...\n");
    dht_singleton_cleanup();

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
